//! Sending dashboard (`/api/overview`): rules shared by its queries.

use serde::Serialize;

/// Go capped the window at one year (366 days).
pub const MAX_WINDOW_SECS: i64 = 31_622_400;

/// Chart bucket size, chosen from the window length like Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// Hour of day 0–23 (windows under a day).
    Hour,
    Day,
    /// Windows of 30 days or more.
    Month,
}

impl Bucket {
    pub fn for_window(start: i64, end: i64) -> Self {
        match end - start {
            secs if secs < 86_400 => Self::Hour,
            secs if secs >= 2_592_000 => Self::Month,
            _ => Self::Day,
        }
    }

    pub fn column_type(self) -> &'static str {
        match self {
            Self::Hour => "hourly",
            Self::Day => "daily",
            Self::Month => "monthly",
        }
    }

    /// `date_trunc` unit (unused for `Hour`).
    pub fn sql_unit(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// Clamps the window to at most a year, keeping its end.
pub fn clamp_window(start: i64, end: i64) -> (i64, i64) {
    (start.max(end - MAX_WINDOW_SECS), end)
}

/// Message counts for a slice of sent mail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Counts {
    pub sends: i64,
    /// Accepted by the receiving server (`sent` with a 2.x.x DSN).
    pub delivered: i64,
    pub bounced: i64,
    /// Messages opened at least once.
    pub opened: i64,
    /// Messages with at least one click.
    pub clicked: i64,
}

impl Counts {
    pub fn failed(&self) -> i64 {
        self.sends - self.delivered
    }
}

/// `part / whole` as a percentage with two decimals (Go's `Round`), 0 when
/// `whole` is 0.
pub fn rate(part: i64, whole: i64) -> f64 {
    if whole <= 0 {
        return 0.0;
    }
    (part as f64 / whole as f64 * 100.0 * 100.0).round() / 100.0
}

/// The dashboard tiles.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dashboard {
    pub sends: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
    pub bounced: i64,
    /// Messages in Postfix's deferred queue right now.
    pub delayed_queue: i64,
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    /// Over delivered mail.
    pub open_rate: f64,
    /// Over delivered mail.
    pub click_rate: f64,
}

impl Dashboard {
    pub fn new(c: Counts, delayed_queue: i64) -> Self {
        Self {
            sends: c.sends,
            delivered: c.delivered,
            opened: c.opened,
            clicked: c.clicked,
            bounced: c.bounced,
            delayed_queue,
            delivery_rate: rate(c.delivered, c.sends),
            bounce_rate: rate(c.bounced, c.sends),
            open_rate: rate(c.opened, c.delivered),
            click_rate: rate(c.clicked, c.delivered),
        }
    }
}

/// One row of the per-provider table. Unlike the dashboard, Go computed
/// open and click rates over all sends here; that is kept.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderRow {
    pub mail_provider: String,
    pub sends: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
    pub bounced: i64,
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
}

impl ProviderRow {
    pub fn new(mail_provider: String, c: Counts) -> Self {
        Self {
            mail_provider,
            sends: c.sends,
            delivered: c.delivered,
            opened: c.opened,
            clicked: c.clicked,
            bounced: c.bounced,
            delivery_rate: rate(c.delivered, c.sends),
            bounce_rate: rate(c.bounced, c.sends),
            open_rate: rate(c.opened, c.sends),
            click_rate: rate(c.clicked, c.sends),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SendTotals {
    pub sends: i64,
    pub delivered: i64,
    pub failed: i64,
    pub delivery_rate: f64,
    pub failure_rate: f64,
}

impl SendTotals {
    pub fn new(c: Counts) -> Self {
        Self {
            sends: c.sends,
            delivered: c.delivered,
            failed: c.failed(),
            delivery_rate: rate(c.delivered, c.sends),
            failure_rate: rate(c.failed(), c.sends),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SendPoint {
    pub x: i64,
    pub sends: i64,
    pub delivered: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SendChart {
    pub column_type: &'static str,
    pub dashboard: SendTotals,
    pub data: Vec<SendPoint>,
}

/// A rate chart point; the field name is the chart's (`bounce_rate`, ...).
#[derive(Debug, Clone, PartialEq)]
pub struct RatePoint {
    pub x: i64,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateChart {
    pub column_type: &'static str,
    pub field: &'static str,
    pub data: Vec<RatePoint>,
}

impl Serialize for RateChart {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeStruct};

        struct Point<'a>(&'a RatePoint, &'static str);
        impl Serialize for Point<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("x", &self.0.x)?;
                map.serialize_entry(self.1, &self.0.value)?;
                map.end()
            }
        }

        let points: Vec<Point> = self.data.iter().map(|p| Point(p, self.field)).collect();
        let mut s = serializer.serialize_struct("RateChart", 2)?;
        s.serialize_field("column_type", self.column_type)?;
        s.serialize_field("data", &points)?;
        s.end()
    }
}

/// Every chart of the overview, from one bucketed series.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Charts {
    pub send_mail_chart: SendChart,
    pub bounce_rate_chart: RateChart,
    pub open_rate_chart: RateChart,
    pub click_rate_chart: RateChart,
}

/// Builds the charts from `(x, counts)` buckets (already complete and in
/// order) and the window's totals. Rates follow Go: bounces over sends,
/// opens over delivered, clicks over opened.
pub fn charts(bucket: Bucket, series: &[(i64, Counts)], totals: Counts) -> Charts {
    let column_type = bucket.column_type();
    let rate_chart = |field: &'static str, f: fn(&Counts) -> f64| RateChart {
        column_type,
        field,
        data: series
            .iter()
            .map(|(x, c)| RatePoint { x: *x, value: f(c) })
            .collect(),
    };
    Charts {
        send_mail_chart: SendChart {
            column_type,
            dashboard: SendTotals::new(totals),
            data: series
                .iter()
                .map(|(x, c)| SendPoint {
                    x: *x,
                    sends: c.sends,
                    delivered: c.delivered,
                    failed: c.failed(),
                })
                .collect(),
        },
        bounce_rate_chart: rate_chart("bounce_rate", |c| rate(c.bounced, c.sends)),
        open_rate_chart: rate_chart("open_rate", |c| rate(c.opened, c.delivered)),
        click_rate_chart: rate_chart("click_rate", |c| rate(c.clicked, c.opened)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_window() {
        assert_eq!(Bucket::for_window(0, 3_600), Bucket::Hour);
        assert_eq!(Bucket::for_window(0, 86_400), Bucket::Day);
        assert_eq!(Bucket::for_window(0, 30 * 86_400), Bucket::Month);
        assert_eq!(
            clamp_window(0, 40_000_000),
            (40_000_000 - MAX_WINDOW_SECS, 40_000_000)
        );
        assert_eq!(clamp_window(100, 200), (100, 200));
    }

    #[test]
    fn rates_round_like_go() {
        assert_eq!(rate(1, 3), 33.33);
        assert_eq!(rate(2, 3), 66.67);
        assert_eq!(rate(5, 0), 0.0);
    }

    #[test]
    fn chart_json_matches_go() {
        let counts = Counts {
            sends: 4,
            delivered: 2,
            bounced: 1,
            opened: 1,
            clicked: 1,
        };
        let charts = charts(Bucket::Day, &[(1_700_000_000, counts)], counts);
        let json = serde_json::to_value(&charts).expect("json");
        assert_eq!(json["bounce_rate_chart"]["column_type"], "daily");
        assert_eq!(
            json["bounce_rate_chart"]["data"][0],
            serde_json::json!({"x": 1_700_000_000, "bounce_rate": 25.0})
        );
        assert_eq!(json["open_rate_chart"]["data"][0]["open_rate"], 50.0);
        assert_eq!(json["click_rate_chart"]["data"][0]["click_rate"], 100.0);
        assert_eq!(
            json["send_mail_chart"]["data"][0],
            serde_json::json!({"x": 1_700_000_000, "sends": 4, "delivered": 2, "failed": 2})
        );
        assert_eq!(json["send_mail_chart"]["dashboard"]["failure_rate"], 50.0);
    }

    #[test]
    fn dashboard_and_provider_denominators() {
        let c = Counts {
            sends: 10,
            delivered: 5,
            bounced: 2,
            opened: 1,
            clicked: 1,
        };
        let d = Dashboard::new(c, 3);
        assert_eq!(
            (d.open_rate, d.click_rate, d.delayed_queue),
            (20.0, 20.0, 3)
        );
        let p = ProviderRow::new("google".into(), c);
        assert_eq!((p.open_rate, p.click_rate), (10.0, 10.0));
    }
}
