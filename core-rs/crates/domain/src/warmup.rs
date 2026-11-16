//! Sender IP warmup (Go: `service/warmup`). A new sending IP starts on a
//! seven-day volume schedule that then grows 30% a day; each mail provider
//! group gets a share of that volume according to its reputation score,
//! which an hourly job recomputes from delivery, bounce, open and click
//! data.
//!
//! Differences from Go:
//! - Finishing a warmup (70,000 messages in the window) sticks. Go set the
//!   period to 0 and, in the same pass, its period update reset it to 21 or
//!   45 days and the progress update pulled progress back below 100.
//! - Limits saturate instead of overflowing: after about 140 days Go's
//!   float-to-int conversion turned the daily limit negative, which reads
//!   as "no sending allowed", so every warmup campaign stopped for good.

/// Seconds in a day.
pub const DAY: i64 = 86_400;

/// The mail provider groups limits are kept for (Go:
/// `consts.MailProviderGroup*`, in Go's evaluation order).
pub const PROVIDER_GROUPS: [&str; 8] = [
    "google", "yahoo", "outlook", "apple", "proton", "zoho", "amazon", "other",
];

/// `(daily, hourly)` limits of the first seven days.
const SCHEDULE: [(i64, i64); 7] = [
    (1000, 100),
    (1500, 150),
    (2000, 200),
    (3000, 300),
    (5000, 500),
    (7000, 700),
    (10_000, 1000),
];
const DAILY_GROWTH: f64 = 1.3;

pub const DEFAULT_PERIOD_DAYS: i32 = 45;
pub const INITIAL_IP_SCORE: i32 = 40;
pub const INITIAL_PROVIDER_SCORE: i32 = 40;
/// IP scores are re-evaluated at most this often.
pub const IP_EVALUATION_INTERVAL: i64 = 3600;
/// Provider scores are re-evaluated at most this often.
pub const PROVIDER_EVALUATION_INTERVAL: i64 = 2 * 3600;

const MIN_SCORE_FOR_SENDING: i32 = 20;
const IP_WINDOW_MS: i64 = 7 * DAY * 1000;
const IP_FULL_SCORING_VOLUME: i64 = 20;
const FINISHED_VOLUME: i64 = 70_000;
const REWARMUP_CHECK_AFTER: i64 = DAY / 2;
const MIN_PROVIDER_SCORE: f64 = 25.0;
const PROVIDER_WINDOW_MS: i64 = 3 * DAY * 1000;
const PROVIDER_FULL_SCORING_VOLUME: i64 = 15;

/// A row of `bm_sender_ip_warmup`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct IpWarmup {
    pub id: i32,
    pub sender_ip: String,
    /// Planned length in days; 0 once the warmup has finished.
    pub period: i32,
    pub score: i32,
    pub last_evaluate_time: i32,
    pub progress: i32,
    pub re_warmups: i32,
    pub begin_time: i32,
    pub end_time: i32,
    pub create_time: i32,
    pub update_time: i32,
}

impl IpWarmup {
    pub fn finished(&self) -> bool {
        self.period == 0 && self.progress >= 100
    }
}

/// A row of `bm_sender_ip_mail_provider`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct ProviderWarmup {
    pub id: i32,
    pub sender_ip: String,
    pub mail_provider: String,
    pub score: i32,
    pub last_evaluate_time: i32,
    pub create_time: i32,
    pub update_time: i32,
}

/// Delivery results of the mail sent from your domains in a window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct SendStats {
    /// Distinct messages handed to Postfix.
    pub messages: i64,
    /// Delivery attempts logged for them (any status).
    pub total: i64,
    pub sent: i64,
    /// Bounces with a 5.x.x status.
    pub hard_bounces: i64,
    /// Other bounces, including those without a status.
    pub soft_bounces: i64,
    pub deferred: i64,
    /// Distinct messages opened, clicked or complained about.
    pub opened: i64,
    pub clicked: i64,
    pub complaints: i64,
}

/// `(daily, hourly)` volume for an IP whose warmup began at `begin_time`.
pub fn base_limits(begin_time: i64, now: i64) -> (i64, i64) {
    if begin_time == 0 {
        return (0, 0);
    }
    let day = ((now - begin_time) / DAY + 1).max(1);
    let len = SCHEDULE.len() as i64;
    if day <= len {
        return SCHEDULE[(day - 1) as usize];
    }
    let (daily, hourly) = SCHEDULE[SCHEDULE.len() - 1];
    let growth = DAILY_GROWTH.powf((day - len) as f64);
    // `as` saturates in Rust; Go's conversion wrapped to a negative value.
    (
        (daily as f64 * growth) as i64,
        (hourly as f64 * growth) as i64,
    )
}

/// Share of the IP's volume a provider group gets, 0.05 to 1.
pub fn provider_rate_factor(score: i32) -> f64 {
    let factor = 0.1 + (f64::from(score) - MIN_PROVIDER_SCORE) / (100.0 - MIN_PROVIDER_SCORE) * 0.9;
    factor.clamp(0.05, 1.0)
}

/// Limits for one provider group: the IP's volume scaled by the group's
/// score, rounded up.
pub fn adjusted_limits((daily, hourly): (i64, i64), provider_score: i32) -> (i64, i64) {
    let factor = provider_rate_factor(provider_score);
    (
        (daily as f64 * factor).ceil() as i64,
        (hourly as f64 * factor).ceil() as i64,
    )
}

/// Seconds a warmup campaign needs for its `unsent` recipients given each
/// provider group's `(daily, hourly)` limits; `-1` when nothing may be sent.
pub fn estimated_seconds(unsent: i64, limits: impl IntoIterator<Item = (i64, i64)>) -> i64 {
    if unsent == 0 {
        return 0;
    }
    let per_hour: i64 = limits
        .into_iter()
        .map(|(daily, hourly)| (hourly as f64).min(daily as f64 / 24.0) as i64)
        .sum();
    if per_hour <= 0 {
        return -1;
    }
    (unsent as f64 / per_hour as f64 * 3600.0) as i64
}

/// Start (Unix millis) of the data an IP evaluation looks at.
pub fn ip_window_start(rec: &IpWarmup, now_ms: i64) -> i64 {
    let mut start = i64::from(rec.last_evaluate_time) * 1000 - IP_WINDOW_MS;
    // The first evaluation, or one after a re-warmup, starts at the begin.
    if rec.create_time == rec.last_evaluate_time || rec.last_evaluate_time < rec.begin_time {
        start = i64::from(rec.begin_time) * 1000;
    }
    if now_ms - start > IP_WINDOW_MS * 2 {
        start = now_ms - IP_WINDOW_MS;
    }
    start
}

/// Start (Unix millis) of the data a provider evaluation looks at.
pub fn provider_window_start(rec: &ProviderWarmup, now_ms: i64) -> i64 {
    let start = i64::from(rec.last_evaluate_time) * 1000 - PROVIDER_WINDOW_MS;
    if now_ms - start > PROVIDER_WINDOW_MS * 2 {
        now_ms - PROVIDER_WINDOW_MS
    } else {
        start
    }
}

fn clamp_score(score: f64) -> i32 {
    // Truncates like Go's `int()`.
    score.clamp(0.0, 100.0) as i32
}

fn rate(part: i64, whole: i64) -> f64 {
    part as f64 / whole as f64
}

/// Outcome of an IP evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpEvaluation {
    pub score: i32,
    /// Enough volume was delivered to end the warmup.
    pub finished: bool,
}

/// New IP score from the window's results. `has_domains` is whether any
/// sending domain is configured.
pub fn evaluate_ip(rec: &IpWarmup, s: &SendStats, has_domains: bool) -> IpEvaluation {
    let mut score = f64::from(rec.score);
    let mut finished = false;
    if s.total == 0 && s.messages == 0 && !has_domains {
        // Nothing to judge.
    } else if s.total > 0 && s.total < IP_FULL_SCORING_VOLUME {
        score += if s.hard_bounces > 0 {
            -1.5
        } else if s.soft_bounces > 0 {
            -0.7
        } else if s.sent > 0 {
            0.2
        } else {
            -0.5
        };
    } else if s.total >= IP_FULL_SCORING_VOLUME {
        finished = s.total >= FINISHED_VOLUME;
        score += (rate(s.sent, s.total) - 0.8).max(0.0) * 30.0;
        score -= rate(s.hard_bounces, s.total) * 10.0;
        score -= rate(s.soft_bounces, s.total) * 5.0;
        score -= rate(s.deferred, s.total) * 2.0;
        if s.sent > 0 {
            score += rate(s.opened, s.sent) * 20.0;
            if s.opened > 0 {
                score += rate(s.clicked, s.opened) * 15.0;
            }
        }
    } else if rec.progress > 65 {
        // Far into the warmup but nothing sent lately.
        if rec.score < 50 {
            score -= 0.3;
        } else if rec.score > 70 {
            score -= 0.2;
        }
    }
    IpEvaluation {
        score: clamp_score(score),
        finished,
    }
}

/// New provider-group score from the window's results.
pub fn evaluate_provider(
    rec: &ProviderWarmup,
    s: &SendStats,
    has_domains: bool,
    ip_progress: i32,
) -> i32 {
    let mut score = f64::from(rec.score);
    if s.total == 0 && s.messages == 0 && !has_domains && rec.mail_provider == "other" {
        // Nothing to judge.
    } else if s.total > 0 && s.total < PROVIDER_FULL_SCORING_VOLUME {
        score += if s.hard_bounces > 0 {
            -0.2
        } else if s.soft_bounces > 0 {
            -0.1
        } else if s.sent > 0 {
            0.3
        } else {
            -0.8
        };
    } else if s.total >= PROVIDER_FULL_SCORING_VOLUME {
        score += (rate(s.sent, s.total) - 0.85).max(0.0) * 40.0;
        score -= rate(s.hard_bounces, s.total) * 1.5;
        score -= rate(s.soft_bounces, s.total) * 0.7;
        score -= rate(s.deferred, s.total) * 0.25;
        if s.sent > 0 {
            score += rate(s.opened, s.sent) * 25.0;
            if s.opened > 0 {
                score += rate(s.clicked, s.opened) * 20.0;
            }
            score -= rate(s.complaints, s.sent) * 200.0;
        }
    } else if ip_progress > 65 {
        if rec.score < 50 {
            score -= 1.5;
        } else if rec.score > 70 {
            score -= 0.5;
        }
    }
    clamp_score(score)
}

/// The warmup period the score calls for, when it differs.
pub fn next_period(rec: &IpWarmup) -> Option<i32> {
    if rec.finished() {
        return None;
    }
    let period = if rec.score < 40 {
        DEFAULT_PERIOD_DAYS + 15 + rec.re_warmups * 5
    } else if rec.score > 80 && rec.progress > 50 {
        (rec.period - 10).max(21)
    } else {
        DEFAULT_PERIOD_DAYS
    }
    .max(7);
    (period != rec.period).then_some(period)
}

/// Progress (0–100) after the time passed, slowed by a poor score and
/// reversed by a very poor one, when it changes.
pub fn next_progress(rec: &IpWarmup, now: i64) -> Option<i32> {
    if rec.begin_time == 0 || rec.period <= 0 {
        return None;
    }
    let days = ((now - i64::from(rec.begin_time)) / DAY).max(0);
    let mut progress = (days as f64 / f64::from(rec.period) * 100.0) as i32;
    let gained = f64::from(progress - rec.progress);
    if rec.score < MIN_SCORE_FOR_SENDING && progress > rec.progress && rec.progress > 10 {
        progress = rec.progress - 5;
    } else if rec.score < 40 && progress > rec.progress {
        progress = rec.progress + (gained * 0.3).max(0.0) as i32;
    } else if rec.score >= 70 && progress > rec.progress {
        progress = rec.progress + (gained * 0.5).max(0.0) as i32;
    }
    let progress = progress.clamp(0, 100);
    (progress != rec.progress).then_some(progress)
}

/// Whether to look at re-warming this IP in this pass.
pub fn rewarmup_check_due(rec: &IpWarmup, now: i64) -> bool {
    rec.progress >= 100 || now - i64::from(rec.update_time) > REWARMUP_CHECK_AFTER
}

/// A warmed-up IP whose reputation fell starts over, with a longer period.
pub fn needs_rewarmup(rec: &IpWarmup) -> bool {
    rec.progress >= 100 && rec.score < 40
}

/// Period of a re-warmup.
pub const REWARMUP_PERIOD_DAYS: i32 = DEFAULT_PERIOD_DAYS + 15;

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn ip() -> IpWarmup {
        IpWarmup {
            id: 1,
            sender_ip: "198.51.100.1".into(),
            period: 45,
            score: 40,
            last_evaluate_time: (NOW - 7200) as i32,
            progress: 0,
            re_warmups: 0,
            begin_time: (NOW - 10 * DAY) as i32,
            end_time: 0,
            create_time: (NOW - 10 * DAY) as i32,
            update_time: (NOW - 7200) as i32,
        }
    }

    fn provider(group: &str, score: i32) -> ProviderWarmup {
        ProviderWarmup {
            id: 1,
            sender_ip: "198.51.100.1".into(),
            mail_provider: group.into(),
            score,
            last_evaluate_time: (NOW - 3 * 3600) as i32,
            create_time: (NOW - DAY) as i32,
            update_time: 0,
        }
    }

    #[test]
    fn schedule_then_growth() {
        assert_eq!(base_limits(0, NOW), (0, 0), "not started");
        assert_eq!(base_limits(NOW, NOW), (1000, 100), "day 1");
        assert_eq!(
            base_limits(NOW + 3600, NOW),
            (1000, 100),
            "begin slightly ahead"
        );
        assert_eq!(base_limits(NOW - 6 * DAY - 1, NOW), (10_000, 1000), "day 7");
        assert_eq!(base_limits(NOW - 7 * DAY, NOW), (13_000, 1300), "day 8");
        // Go wrapped to a negative limit here and stopped all sending.
        let (daily, hourly) = base_limits(NOW - 400 * DAY, NOW);
        assert_eq!((daily, hourly), (i64::MAX, i64::MAX));
        assert!(adjusted_limits((daily, hourly), 40).0 > 0);
    }

    #[test]
    fn provider_share() {
        assert!((provider_rate_factor(40) - 0.28).abs() < 1e-9);
        assert_eq!(provider_rate_factor(0), 0.05);
        assert_eq!(provider_rate_factor(100), 1.0);
        // Values computed with Go's expressions: 100 * 0.28 is
        // 28.000000000000004 in floating point, so it rounds up to 29.
        assert_eq!(adjusted_limits((1000, 100), 40), (280, 29));
        assert_eq!(adjusted_limits((13_000, 1300), 55), (5981, 599));
    }

    #[test]
    fn estimate() {
        assert_eq!(estimated_seconds(0, []), 0);
        assert_eq!(estimated_seconds(10, [(0, 0)]), -1);
        // min(28, 280/24 = 11.67) = 11 per hour per group, 8 groups.
        assert_eq!(estimated_seconds(880, [(280, 28); 8]), 36_000);
    }

    #[test]
    fn ip_scores() {
        let rec = ip();
        let none = SendStats::default();
        assert_eq!(evaluate_ip(&rec, &none, false).score, 40);
        // Low volume: a hard bounce costs 1.5, a success adds 0.2, which
        // the integer column truncates away (as in Go).
        let low = SendStats {
            total: 5,
            sent: 4,
            hard_bounces: 1,
            messages: 5,
            ..none
        };
        assert_eq!(evaluate_ip(&rec, &low, true).score, 38);
        let low = SendStats {
            total: 5,
            sent: 5,
            messages: 5,
            ..none
        };
        assert_eq!(evaluate_ip(&rec, &low, true).score, 40);

        // 100 attempts: 95 sent, 2 hard, 1 soft, 2 deferred; 40 opens, 8 clicks.
        let full = SendStats {
            messages: 100,
            total: 100,
            sent: 95,
            hard_bounces: 2,
            soft_bounces: 1,
            deferred: 2,
            opened: 40,
            clicked: 8,
            complaints: 0,
        };
        // 40 + 0.15*30 - 0.2 - 0.05 - 0.04 + 40/95*20 + 8/40*15 = 55.63...
        let e = evaluate_ip(&rec, &full, true);
        assert_eq!(
            e,
            IpEvaluation {
                score: 55,
                finished: false
            }
        );
        let done = SendStats {
            total: 70_000,
            sent: 70_000,
            messages: 70_000,
            ..none
        };
        assert!(evaluate_ip(&rec, &done, true).finished);

        // Idle late in the warmup slowly loses score.
        let idle = IpWarmup {
            progress: 70,
            score: 45,
            ..ip()
        };
        assert_eq!(evaluate_ip(&idle, &none, true).score, 44);
        assert_eq!(
            evaluate_ip(
                &IpWarmup {
                    score: 100,
                    ..idle.clone()
                },
                &full,
                true
            )
            .score,
            100
        );
    }

    #[test]
    fn provider_scores() {
        let none = SendStats::default();
        assert_eq!(
            evaluate_provider(&provider("other", 40), &none, false, 0),
            40
        );
        // Not "other": an idle group is judged on IP progress.
        assert_eq!(
            evaluate_provider(&provider("google", 40), &none, false, 70),
            38
        );
        assert_eq!(
            evaluate_provider(&provider("google", 40), &none, true, 10),
            40
        );
        let full = SendStats {
            messages: 20,
            total: 20,
            sent: 19,
            hard_bounces: 1,
            opened: 10,
            clicked: 1,
            complaints: 1,
            ..none
        };
        // 40 + 0.1*40 - 0.075 + 10/19*25 + 0.1*20 - 1/19*200 = 48.57...
        assert_eq!(
            evaluate_provider(&provider("google", 40), &full, true, 0),
            48
        );
    }

    #[test]
    fn period_and_progress() {
        let rec = ip();
        assert_eq!(next_period(&rec), None);
        assert_eq!(
            next_period(&IpWarmup {
                score: 30,
                re_warmups: 2,
                ..ip()
            }),
            Some(70)
        );
        assert_eq!(
            next_period(&IpWarmup {
                score: 90,
                progress: 60,
                period: 25,
                ..ip()
            }),
            Some(21)
        );
        // 10 of 45 days = 22%; a score of 40 progresses normally.
        assert_eq!(next_progress(&rec, NOW), Some(22));
        // A good score moves half the way, a poor one 30%, a very poor one back.
        assert_eq!(
            next_progress(
                &IpWarmup {
                    score: 75,
                    progress: 10,
                    ..ip()
                },
                NOW
            ),
            Some(16)
        );
        assert_eq!(
            next_progress(
                &IpWarmup {
                    score: 35,
                    progress: 10,
                    ..ip()
                },
                NOW
            ),
            Some(13)
        );
        assert_eq!(
            next_progress(
                &IpWarmup {
                    score: 10,
                    progress: 15,
                    ..ip()
                },
                NOW
            ),
            Some(10)
        );
        assert_eq!(
            next_progress(
                &IpWarmup {
                    begin_time: 0,
                    ..ip()
                },
                NOW
            ),
            None
        );
    }

    #[test]
    fn finished_warmups_stay_finished() {
        let done = IpWarmup {
            period: 0,
            progress: 100,
            score: 60,
            ..ip()
        };
        assert!(done.finished());
        assert_eq!(next_period(&done), None, "Go reset the period here");
        assert_eq!(next_progress(&done, NOW), None);
        assert!(rewarmup_check_due(&done, NOW));
        assert!(!needs_rewarmup(&done));
        assert!(needs_rewarmup(&IpWarmup { score: 30, ..done }));
    }

    #[test]
    fn windows() {
        let rec = ip();
        let now_ms = NOW * 1000;
        assert_eq!(
            ip_window_start(&rec, now_ms),
            now_ms - 7_200_000 - IP_WINDOW_MS
        );
        let first = IpWarmup {
            last_evaluate_time: rec.create_time,
            ..ip()
        };
        // Begin was 10 days ago: more than 14 days of window is capped.
        assert_eq!(
            ip_window_start(&first, now_ms),
            i64::from(rec.begin_time) * 1000
        );
        // After a re-warmup the window starts at the new begin.
        let restarted = IpWarmup {
            create_time: 0,
            last_evaluate_time: (NOW - 30 * DAY) as i32,
            ..ip()
        };
        assert_eq!(
            ip_window_start(&restarted, now_ms),
            i64::from(rec.begin_time) * 1000
        );
        // A long-unevaluated IP looks back one window only.
        let stale = IpWarmup {
            create_time: 0,
            begin_time: (NOW - 60 * DAY) as i32,
            last_evaluate_time: (NOW - 30 * DAY) as i32,
            ..ip()
        };
        assert_eq!(ip_window_start(&stale, now_ms), now_ms - IP_WINDOW_MS);
        let p = provider("google", 40);
        assert_eq!(
            provider_window_start(&p, now_ms),
            i64::from(p.last_evaluate_time) * 1000 - PROVIDER_WINDOW_MS
        );
    }
}
