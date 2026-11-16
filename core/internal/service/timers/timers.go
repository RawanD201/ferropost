package timers

import (
	"billionmail-core/internal/service/abnormal_recipient"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/fail2ban"
	"billionmail-core/internal/service/log_maintenance"
	"billionmail-core/internal/service/mail_boxes"
	"billionmail-core/internal/service/mail_service"
	"billionmail-core/internal/service/maillog_stat"
	"billionmail-core/internal/service/multi_ip_domain"
	"billionmail-core/internal/service/relay"
	"billionmail-core/internal/service/warmup"
	"context"
	"os"
	"strings"
	"time"

	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/frame/g"
)

// Start Start initializes and starts all the necessary timers for the service.
func Start(ctx context.Context) (err error) {
	g.Log().Debug(ctx, "Starting timers...")

	// Normalize mailboxes to lowercase
	if !OwnedByRust("mailboxes") {
		gtimer.AddOnce(500*time.Millisecond, func() {
			g.Log().Debug(ctx, "Mailboxes normalization started")

			err = mail_boxes.NormalizeMailboxes()

			if err != nil {
				g.Log().Warning(ctx, "NormalizeMailboxes failed: ", err)
				err = nil // Ignore the error to allow the service to continue
			} else {
				g.Log().Debug(ctx, "Mailboxes normalized successfully")
			}
		})
	}

	// Start DNS Records checking, unless the Rust core runs it.
	if !OwnedByRust("domains") {
		// Ensure the DNS records are fresh on startup
		gtimer.AddOnce(500*time.Millisecond, func() {
			// repair DKIM signing config
			err = domains.RepairDKIMSigningConfig(ctx)

			if err != nil {
				g.Log().Warning(ctx, "RepairDKIMSigningConfig failed: ", err)
				err = nil
			}

			domains.FreshRecords(ctx)
		})
		// Check DNS Records every 5 minutes
		gtimer.Add(5*time.Minute, func() {
			domains.FreshRecords(ctx)
		})
	}

	// Start maillog analysis and aggregation, unless the Rust core runs them.
	if !OwnedByRust("maillog") {
		gtimer.AddOnce(time.Second, func() {
			me := maillog_stat.NewMallogEventHandler("", 1*time.Second)
			me.Start()
		})

		gtimer.AddOnce(time.Second, func() {
			maillog_stat.AggregateMaillogsTask(1 * time.Minute)
		})
	} else {
		g.Log().Info(ctx, "maillog analysis is run by the Rust core")
	}

	// Start console panel baseurl update timer
	gtimer.AddOnce(100*time.Millisecond, func() {
		domains.UpdateBaseURL(ctx)
	})
	gtimer.Add(5*time.Minute, func() {
		domains.UpdateBaseURL(ctx)
	})

	g.Log().Debug(ctx, "Start timers complete")

	// Fix Postfix main configuration and Rspamd DKIM signing config
	gtimer.AddOnce(5*time.Second, func() {
		if !OwnedByRust("mail_services") {
			mail_service.FixPostfixMainConfig(ctx)
		}
		if !OwnedByRust("domains") {
			mail_service.FixRspamdDKIMSigningConfig(ctx)
		}
		if !OwnedByRust("ssl") {
			mail_service.FixDovecotSSLConfig(ctx)
		}
	})

	// ========== Mail task processing: one executor per task ==========
	if !OwnedByRust("campaigns") {
		gtimer.Add(5*time.Second, func() {
			batch_mail.ProcessEmailTasks(ctx)
		})

		// Idle actuators are cleaned every 10 minutes
		gtimer.Add(10*time.Minute, func() {
			batch_mail.CleanupIdleExecutors()
			g.Log().Debug(ctx, "Idle task executors cleanup completed")
		})
	}

	// Test the smtp relay configuration connection status
	if !OwnedByRust("relay") {
		gtimer.AddOnce(5*time.Second, func() {
			relay.UpdateRelayStatus(ctx)
		})

		gtimer.Add(5*time.Minute, func() {
			relay.UpdateRelayStatus(ctx)
		})
	}
	// Renew certificates, once at start-up, unless the Rust core does.
	if !OwnedByRust("ssl") {
		gtimer.AddOnce(1*time.Second, func() {
			domains.AutoRenewSSL(ctx)
		})

		gtimer.Add(24*time.Hour, func() {
			domains.AutoRenewSSL(ctx)
		})
	}

	if !OwnedByRust("api_mail") {
		gtimer.Add(1*time.Minute, func() {
			//gtimer.Add(5*time.Second, func() {
			batch_mail.ProcessApiMailQueueWithLock(ctx)
		})
	}

	// Sender IP warmup and mail provider warmup
	if !OwnedByRust("warmup") {
		gtimer.Add(time.Hour, func() {
			warmup.SenderIpWarmup().PeriodicTask(ctx)
			warmup.SenderIpMailProvider().PeriodicTaskForProviders(ctx)
		})
	}

	// fail2ban access logs detection
	if !OwnedByRust("log_maintenance") {
		gtimer.AddOnce(800*time.Millisecond, fail2ban.NewAccessLogDetection().Start)
	}

	if !OwnedByRust("abnormal_recipient") {
		gtimer.Add(30*time.Minute, func() {
			abnormal_recipient.AbnormalRecipientAutoStat(context.Background())
		})
	}

	// Regularly update the success and failure data of marketing tasks
	if !OwnedByRust("campaigns") {
		gtimer.Add(1*time.Minute, func() {
			batch_mail.UpdateTaskJoinMailstat(ctx)
		})
	}

	// First sync of SMTP relay configurations to Postfix after refactoring
	if !OwnedByRust("relay") {
		gtimer.AddOnce(3*time.Second, func() {
			relay.CheckRelayFirstSync(ctx)
		})
	}

	// update iptable
	if !OwnedByRust("multi_ip") {
		gtimer.AddOnce(3*time.Second, func() {
			multi_ip_domain.ReapplyAllIptablesRules(ctx)
		})
	}

	if !OwnedByRust("mailboxes") {
		// Updated: Used space in the mailbox
		gtimer.AddOnce(20*time.Second, func() {
			mail_boxes.UpdateMailboxesUsedSpace()
		})

		gtimer.Add(60*time.Minute, func() {
			mail_boxes.UpdateMailboxesUsedSpace()
		})

		// Check the email quota and the alert for exceeding the quota
		gtimer.AddOnce(1*time.Minute, func() {
			mail_boxes.CheckMailboxesQuotaAlerts(ctx)
		})

		gtimer.Add(60*time.Minute, func() {
			mail_boxes.CheckMailboxesQuotaAlerts(ctx)
		})

		// Initialize the quota plugin and update the quota usage status of the domain name and email
		gtimer.AddOnce(1*time.Second, func() {
			err := mail_boxes.InitQuotaPluginAndUpdateUsedSpace(ctx)
			if err != nil {
				g.Log().Warning(ctx, "Initialize the quota plugin and update the quota usage status of the domain name and email,  failed: ", err)
				err = nil
			}
		})
	}

	if !OwnedByRust("relay") {
		gtimer.AddOnce(1*time.Minute, func() {
			relay.EnsurePostfixConfExists(ctx)
		})
	}

	// Check the domain name blacklist
	if !OwnedByRust("blacklist") {
		gtimer.Add(24*time.Hour, func() {
			domains.CheckDomainsBlacklist(ctx)
		})
	}

	if !OwnedByRust("log_maintenance") {
		gtimer.Add(24*time.Hour, func() {
			log_maintenance.CompressAndCleanupLogs(ctx)
		})
	}

	g.Log().Debug(ctx, "All timers started successfully")
	return nil
}

// OwnedByRust reports whether a background job has moved to the Rust core.
// FERROPOST_RUST_JOBS lists such jobs (comma-separated); the Rust process
// reads the same variable and runs exactly those, so no job runs twice.
func OwnedByRust(job string) bool {
	for _, name := range strings.Split(os.Getenv("FERROPOST_RUST_JOBS"), ",") {
		if strings.TrimSpace(name) == job {
			return true
		}
	}
	return false
}
