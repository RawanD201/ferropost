-- The schema BillionMail's Go core created at every start
-- (`service/database_initialization`), as one idempotent migration: it
-- creates a new database and leaves one Go already made as it is.

-- Options ---------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_options (
    name VARCHAR(255) NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- Operation log -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_operation_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    type VARCHAR(64) NOT NULL,
    log TEXT NOT NULL,
    ip VARCHAR(64) NOT NULL,
    info TEXT NOT NULL,
    addtime INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE INDEX IF NOT EXISTS idx_log_user_time ON bm_operation_logs(user_id, addtime);
CREATE INDEX IF NOT EXISTS idx_log_type ON bm_operation_logs(type);
CREATE INDEX IF NOT EXISTS idx_log_addtime ON bm_operation_logs(addtime);
CREATE INDEX IF NOT EXISTS idx_log_ip ON bm_operation_logs(ip);
CREATE INDEX IF NOT EXISTS idx_log_log ON bm_operation_logs(log);
CREATE INDEX IF NOT EXISTS idx_log_info ON bm_operation_logs(info);

-- Certificates ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS letsencrypts (
    cert_id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL DEFAULT 0,
    issuer TEXT NOT NULL DEFAULT '',
    not_after TEXT NOT NULL DEFAULT '',
    not_before TEXT NOT NULL DEFAULT '',
    dns TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT '',
    dns_provider TEXT NOT NULL DEFAULT '',
    dns_provider_token TEXT NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    certificate TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL DEFAULT '',
    endtime INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    progress TEXT NOT NULL DEFAULT '',
    error_info TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS renew_logs (
    renew_id SERIAL PRIMARY KEY,
    cert_id INTEGER NOT NULL DEFAULT 0,
    account_id INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 0,
    progress TEXT NOT NULL DEFAULT '',
    error_info TEXT NOT NULL DEFAULT '',
    renew_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);

-- Dedicated sending IPs -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_multi_ip_domain (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    outbound_ip VARCHAR(45) NOT NULL,
    network_name VARCHAR(100) NOT NULL,
    subnet VARCHAR(20) NOT NULL,
    postfix_ip VARCHAR(45) NOT NULL,
    aliases VARCHAR(255) NOT NULL,
    smtp_server_name VARCHAR(100) NOT NULL,
    active SMALLINT NOT NULL DEFAULT 1,
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    UNIQUE(domain, outbound_ip)
);
CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_active ON bm_multi_ip_domain(active);
CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_domain ON bm_multi_ip_domain(domain);
CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_outbound_ip ON bm_multi_ip_domain(outbound_ip);

-- Sending IP warmup ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_sender_ip_warmup (
    id SERIAL PRIMARY KEY,
    sender_ip TEXT NOT NULL DEFAULT '',
    period INTEGER NOT NULL DEFAULT 45,
    score INTEGER NOT NULL DEFAULT 40,
    last_evaluate_time INTEGER NOT NULL DEFAULT 0,
    progress INTEGER NOT NULL DEFAULT 0,
    re_warmups INTEGER NOT NULL DEFAULT 0,
    begin_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    end_time INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE INDEX IF NOT EXISTS idx_bm_sender_ip_warmup_sender_ip ON bm_sender_ip_warmup (sender_ip);
CREATE TABLE IF NOT EXISTS bm_sender_ip_mail_provider (
    id SERIAL PRIMARY KEY,
    sender_ip TEXT NOT NULL DEFAULT '',
    mail_provider TEXT NOT NULL DEFAULT 'other',
    score INTEGER NOT NULL DEFAULT 40,
    last_evaluate_time INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE INDEX IF NOT EXISTS idx_bm_sender_ip_mail_provider_sender_ip ON bm_sender_ip_mail_provider (sender_ip, mail_provider);
CREATE TABLE IF NOT EXISTS bm_campaign_warmup (
    id SERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL DEFAULT 0,
    warmup_id BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_bm_campaign_warmup_task_id_warmup_id ON bm_campaign_warmup (task_id, warmup_id);

-- Accounts and roles --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account (
    account_id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status INT NOT NULL DEFAULT 1,
    language VARCHAR(50) NOT NULL DEFAULT 'en',
    last_login_time INT NOT NULL DEFAULT 0,
    create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE TABLE IF NOT EXISTS role (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    status INT NOT NULL DEFAULT 1,
    create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE TABLE IF NOT EXISTS permission (
    permission_id SERIAL PRIMARY KEY,
    permission_name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    module VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(64) NOT NULL,
    status INT NOT NULL DEFAULT 1,
    create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(module, action, resource)
);
CREATE TABLE IF NOT EXISTS account_role (
    id SERIAL PRIMARY KEY,
    account_id INT NOT NULL,
    role_id INT NOT NULL,
    create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(account_id, role_id),
    FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS role_permission (
    id SERIAL PRIMARY KEY,
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE
);

-- Contacts, templates and campaigns -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_contact_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    token VARCHAR(30) NOT NULL DEFAULT '',
    double_optin SMALLINT NOT NULL DEFAULT 0,
    welcome_mail_html TEXT DEFAULT '',
    welcome_mail_drag TEXT DEFAULT '',
    confirm_mail_html TEXT DEFAULT '',
    confirm_mail_drag TEXT DEFAULT '',
    success_url TEXT DEFAULT '',
    confirm_url TEXT DEFAULT '',
    already_url TEXT DEFAULT '',
    subscribe_form TEXT DEFAULT '',
    confirm_subject TEXT DEFAULT '',
    welcome_subject TEXT DEFAULT '',
    send_welcome_email SMALLINT NOT NULL DEFAULT 0,
    unsubscribe_mail_html TEXT DEFAULT '',
    unsubscribe_mail_drag TEXT DEFAULT '',
    unsubscribe_subject TEXT DEFAULT 'You''re unsubscribed',
    unsubscribe_redirect_url TEXT DEFAULT '',
    send_unsubscribe_email SMALLINT NOT NULL DEFAULT 0,
    UNIQUE(name)
);
CREATE TABLE IF NOT EXISTS bm_contacts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    group_id INTEGER,
    active INTEGER DEFAULT 1,
    task_id INTEGER DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    status INTEGER DEFAULT 0,
    attribs JSONB DEFAULT '{}'::jsonb,
    last_active_at INTEGER DEFAULT 0,
    FOREIGN KEY (group_id) REFERENCES bm_contact_groups(id) ON DELETE SET NULL,
    UNIQUE(group_id, email)
);
CREATE TABLE IF NOT EXISTS email_templates (
    id SERIAL PRIMARY KEY,
    temp_name VARCHAR(255),
    chat_id VARCHAR(255),
    add_type SMALLINT NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    render TEXT NOT NULL DEFAULT '',
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(temp_name)
);
CREATE TABLE IF NOT EXISTS email_tasks (
    id SERIAL PRIMARY KEY,
    task_name VARCHAR(255) NOT NULL,
    addresser VARCHAR(320) NOT NULL,
    subject TEXT,
    full_name VARCHAR(255),
    remark TEXT,
    recipient_count INTEGER NOT NULL,
    task_process SMALLINT NOT NULL DEFAULT 0,
    pause SMALLINT NOT NULL DEFAULT 0,
    template_id INTEGER NOT NULL,
    is_record SMALLINT NOT NULL DEFAULT 0,
    unsubscribe SMALLINT NOT NULL DEFAULT 0,
    threads INTEGER NOT NULL DEFAULT 0,
    etypes VARCHAR(320) NOT NULL DEFAULT '1',
    track_open SMALLINT NOT NULL DEFAULT 1,
    track_click SMALLINT NOT NULL DEFAULT 1,
    start_time INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    active SMALLINT NOT NULL DEFAULT 0,
    add_type SMALLINT NOT NULL DEFAULT 0,
    sends_count INTEGER NOT NULL DEFAULT 0,
    delivered_count INTEGER NOT NULL DEFAULT 0,
    bounced_count INTEGER NOT NULL DEFAULT 0,
    deferred_count INTEGER NOT NULL DEFAULT 0,
    group_id INTEGER NOT NULL DEFAULT 0,
    stats_update_time INTEGER NOT NULL DEFAULT 0,
    tag_ids TEXT DEFAULT '',
    tag_logic VARCHAR(10) DEFAULT 'AND'
);
CREATE TABLE IF NOT EXISTS recipient_info (
    id SERIAL PRIMARY KEY,
    task_id INTEGER NOT NULL,
    recipient VARCHAR(320) NOT NULL,
    is_sent SMALLINT DEFAULT 0,
    sent_time INTEGER NOT NULL DEFAULT 0,
    message_id TEXT NOT NULL,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    FOREIGN KEY (task_id) REFERENCES email_tasks(id) ON DELETE CASCADE,
    UNIQUE(task_id, recipient)
);
CREATE TABLE IF NOT EXISTS unsubscribe_records (
    id SERIAL PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    group_id INTEGER,
    template_id INTEGER,
    task_id INTEGER,
    unsubscribe_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE TABLE IF NOT EXISTS abnormal_recipient (
    id SERIAL PRIMARY KEY,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    recipient VARCHAR(320) NOT NULL,
    count INTEGER NOT NULL,
    description VARCHAR(255) NOT NULL,
    add_type SMALLINT NOT NULL DEFAULT 0,
    UNIQUE(recipient)
);
CREATE TABLE IF NOT EXISTS api_templates (
    id SERIAL PRIMARY KEY,
    api_key VARCHAR(64) NOT NULL,
    api_name VARCHAR(255) NOT NULL,
    template_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    addresser VARCHAR(320) NOT NULL,
    full_name VARCHAR(255),
    unsubscribe SMALLINT NOT NULL DEFAULT 0,
    track_open SMALLINT NOT NULL DEFAULT 1,
    track_click SMALLINT NOT NULL DEFAULT 1,
    active SMALLINT NOT NULL DEFAULT 1,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    expire_time INTEGER DEFAULT 0,
    last_key_update_time INTEGER DEFAULT 0,
    UNIQUE(api_key)
);
CREATE TABLE IF NOT EXISTS api_mail_logs (
    id SERIAL PRIMARY KEY,
    api_id INTEGER NOT NULL,
    recipient VARCHAR(320) NOT NULL,
    message_id TEXT NOT NULL,
    addresser VARCHAR(320) NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    error_message TEXT,
    attribs JSONB DEFAULT '{}'::jsonb,
    send_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE TABLE IF NOT EXISTS api_ip_whitelist (
    id SERIAL PRIMARY KEY,
    api_id INTEGER NOT NULL,
    ip VARCHAR(45) NOT NULL,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    FOREIGN KEY (api_id) REFERENCES api_templates(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS bm_tags (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(group_id, name)
);
CREATE TABLE IF NOT EXISTS bm_contact_tags (
    id SERIAL PRIMARY KEY,
    contact_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    UNIQUE(contact_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_unsubscribe_email ON unsubscribe_records (email);
CREATE INDEX IF NOT EXISTS idx_unsubscribe_time ON unsubscribe_records (unsubscribe_time);
CREATE INDEX IF NOT EXISTS idx_bm_contacts_email ON bm_contacts (email);
CREATE INDEX IF NOT EXISTS idx_bm_contacts_active ON bm_contacts (active);
CREATE INDEX IF NOT EXISTS idx_abnormal_recipient_count ON abnormal_recipient (recipient, count);
CREATE INDEX IF NOT EXISTS idx_group_email ON bm_contacts(group_id, email);
CREATE INDEX IF NOT EXISTS idx_api_mail_logs_api_id ON api_mail_logs (api_id);
CREATE INDEX IF NOT EXISTS idx_api_mail_logs_recipient ON api_mail_logs (recipient);
CREATE INDEX IF NOT EXISTS idx_api_mail_logs_message_id ON api_mail_logs (message_id);
CREATE INDEX IF NOT EXISTS idx_recipient_info_task_id ON recipient_info(task_id);
CREATE INDEX IF NOT EXISTS idx_recipient_info_is_sent ON recipient_info(is_sent);
CREATE INDEX IF NOT EXISTS idx_recipient_info_message_id ON recipient_info(message_id);
CREATE INDEX IF NOT EXISTS idx_recipient_info_task_sent ON recipient_info(task_id, is_sent);
CREATE INDEX IF NOT EXISTS idx_email_tasks_task_process ON email_tasks(task_process);
CREATE INDEX IF NOT EXISTS idx_bm_tags_group_id ON bm_tags(group_id);
CREATE INDEX IF NOT EXISTS idx_bm_contact_tags_contact_id ON bm_contact_tags(contact_id);
CREATE INDEX IF NOT EXISTS idx_bm_contact_tags_tag_id ON bm_contact_tags(tag_id);

-- Columns older installs lack (Go's AddColumnIfNotExists).
ALTER TABLE bm_contacts ADD COLUMN IF NOT EXISTS attribs JSONB DEFAULT '{}'::jsonb;
ALTER TABLE bm_contacts ADD COLUMN IF NOT EXISTS status INTEGER NOT NULL DEFAULT 1;
ALTER TABLE bm_contacts ADD COLUMN IF NOT EXISTS last_active_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE api_mail_logs ADD COLUMN IF NOT EXISTS status SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE api_mail_logs ADD COLUMN IF NOT EXISTS error_message TEXT DEFAULT '';
ALTER TABLE api_mail_logs ADD COLUMN IF NOT EXISTS create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW());
ALTER TABLE api_mail_logs ADD COLUMN IF NOT EXISTS attribs JSONB DEFAULT '{}'::jsonb;
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS token VARCHAR(30) NOT NULL DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS double_optin SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS success_url TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS confirm_url TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS already_url TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS subscribe_form TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS welcome_mail_html TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS welcome_mail_drag TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS confirm_mail_html TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS confirm_mail_drag TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS confirm_subject TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS welcome_subject TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS send_welcome_email SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS unsubscribe_mail_html TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS unsubscribe_mail_drag TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS unsubscribe_subject TEXT DEFAULT 'You''re unsubscribed';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS unsubscribe_redirect_url TEXT DEFAULT '';
ALTER TABLE bm_contact_groups ADD COLUMN IF NOT EXISTS send_unsubscribe_email SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE email_templates ADD COLUMN IF NOT EXISTS chat_id VARCHAR(255) DEFAULT '';
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS sends_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS delivered_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS bounced_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS deferred_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS stats_update_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS group_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS tag_ids TEXT DEFAULT '';
ALTER TABLE email_tasks ADD COLUMN IF NOT EXISTS tag_logic VARCHAR(10) DEFAULT 'AND';
ALTER TABLE api_templates ADD COLUMN IF NOT EXISTS group_id INTEGER NOT NULL DEFAULT 0;

-- Foreign keys Go dropped: records outlive what they point to.
DO $$
DECLARE
    found RECORD;
BEGIN
    FOR found IN
        SELECT tc.table_name, tc.constraint_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
         WHERE tc.constraint_type = 'FOREIGN KEY'
           AND tc.table_schema = current_schema()
           AND (tc.table_name, kcu.column_name) IN (
               ('unsubscribe_records', 'group_id'), ('unsubscribe_records', 'template_id'),
               ('unsubscribe_records', 'task_id'), ('email_tasks', 'template_id'))
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', found.table_name, found.constraint_name);
    END LOOP;
END $$;

-- Mail log statistics -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mailstat_removed (
    postfix_message_id TEXT PRIMARY KEY,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED
);
CREATE INDEX IF NOT EXISTS removed_logTime ON mailstat_removed (log_time);
CREATE INDEX IF NOT EXISTS removed_logTime_millis ON mailstat_removed (log_time_millis);
CREATE TABLE IF NOT EXISTS mailstat_message_ids (
    postfix_message_id TEXT PRIMARY KEY,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    message_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS messageIds_logTime ON mailstat_message_ids (log_time);
CREATE INDEX IF NOT EXISTS messageIds_logTime_millis ON mailstat_message_ids (log_time_millis);
CREATE INDEX IF NOT EXISTS messageIds_messageId ON mailstat_message_ids (message_id);
CREATE TABLE IF NOT EXISTS mailstat_senders (
    postfix_message_id TEXT PRIMARY KEY,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    size INTEGER NOT NULL DEFAULT 0,
    sender TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS senders_logTime_size_sender ON mailstat_senders (log_time, size, sender);
CREATE INDEX IF NOT EXISTS senders_logTime_millis ON mailstat_senders (log_time_millis);
CREATE TABLE IF NOT EXISTS mailstat_send_mails (
    postfix_message_id TEXT PRIMARY KEY,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    status TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    mail_provider TEXT NOT NULL DEFAULT '',
    delay REAL NOT NULL DEFAULT 0,
    delays TEXT NOT NULL DEFAULT '',
    dsn TEXT NOT NULL DEFAULT '',
    relay TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sendMails_logTime_status_recipient ON mailstat_send_mails (log_time, status, recipient);
CREATE INDEX IF NOT EXISTS sendMails_logTime_millis ON mailstat_send_mails (log_time_millis);
CREATE INDEX IF NOT EXISTS sendMails_logTime_status_mailProvider ON mailstat_send_mails (log_time, status, mail_provider);
CREATE TABLE IF NOT EXISTS mailstat_receive_mails (
    postfix_message_id TEXT PRIMARY KEY,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    status TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    delay REAL NOT NULL DEFAULT 0,
    delays TEXT NOT NULL DEFAULT '',
    dsn TEXT NOT NULL DEFAULT '',
    relay TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS receiveMails_logTime_status_recipient ON mailstat_receive_mails (log_time, status, recipient);
CREATE INDEX IF NOT EXISTS receiveMails_logTime_millis ON mailstat_receive_mails (log_time_millis);
CREATE TABLE IF NOT EXISTS mailstat_deferred_mails (
    id SERIAL PRIMARY KEY,
    postfix_message_id TEXT NOT NULL DEFAULT '',
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    delay REAL NOT NULL DEFAULT 0,
    delays TEXT NOT NULL DEFAULT '',
    dsn TEXT NOT NULL DEFAULT '',
    relay TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS deferredMails_postfixMessageId_logTime ON mailstat_deferred_mails (postfix_message_id, log_time);
CREATE INDEX IF NOT EXISTS deferredMails_logTime_millis ON mailstat_deferred_mails (log_time_millis);
CREATE TABLE IF NOT EXISTS mailstat_opened (
    id SERIAL PRIMARY KEY,
    campaign_id INTEGER NOT NULL DEFAULT 0,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    recipient TEXT NOT NULL DEFAULT '',
    postfix_message_id TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS opened_postfixMessageId_logTime ON mailstat_opened (postfix_message_id, log_time);
CREATE INDEX IF NOT EXISTS opened_logTime_millis ON mailstat_opened (log_time_millis);
CREATE INDEX IF NOT EXISTS opened_campaignId_logTime ON mailstat_opened (campaign_id, log_time);
CREATE TABLE IF NOT EXISTS mailstat_clicked (
    id SERIAL PRIMARY KEY,
    campaign_id INTEGER NOT NULL DEFAULT 0,
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
    recipient TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    postfix_message_id TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS clicked_postfixMessageId_logTime_url ON mailstat_clicked (postfix_message_id, log_time, url);
CREATE INDEX IF NOT EXISTS clicked_logTime_millis ON mailstat_clicked (log_time_millis);
CREATE INDEX IF NOT EXISTS clicked_campaignId_logTime_url_recipient ON mailstat_clicked (campaign_id, log_time, url, recipient);
CREATE TABLE IF NOT EXISTS mailstat_complaints (
    id SERIAL PRIMARY KEY,
    postfix_message_id TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
    log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED
);
CREATE INDEX IF NOT EXISTS complaints_postfixMessageId_logTime ON mailstat_complaints (postfix_message_id, log_time);
CREATE INDEX IF NOT EXISTS complaints_logTime_millis ON mailstat_complaints (log_time_millis);

-- Mail server (also read by Postfix and Dovecot) ------------------------------------------------
CREATE TABLE IF NOT EXISTS domain (
    domain VARCHAR(255) NOT NULL,
    a_record VARCHAR(255) NOT NULL DEFAULT '',
    mailboxes INT NOT NULL DEFAULT 50,
    mailbox_quota BIGINT NOT NULL DEFAULT 5368709120,
    quota BIGINT NOT NULL DEFAULT 10737418240,
    rate_limit INT DEFAULT 12,
    create_time INT NOT NULL DEFAULT 0,
    active SMALLINT NOT NULL DEFAULT 1,
    urls TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    hasbrandinfo SMALLINT NOT NULL DEFAULT 0,
    current_usage BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (domain)
);
CREATE TABLE IF NOT EXISTS mailbox (
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    password_encode VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    is_admin SMALLINT NOT NULL DEFAULT 0,
    maildir VARCHAR(255) NOT NULL,
    quota BIGINT NOT NULL DEFAULT 0,
    local_part VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0,
    active SMALLINT NOT NULL DEFAULT 1,
    used_quota BIGINT NOT NULL DEFAULT 0,
    quota_active SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (username)
);
CREATE TABLE IF NOT EXISTS alias (
    address VARCHAR(255) NOT NULL,
    goto TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0,
    active SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (address)
);
CREATE TABLE IF NOT EXISTS bm_bcc (
    id SERIAL PRIMARY KEY,
    type TEXT NOT NULL,
    address TEXT NOT NULL,
    goto TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0,
    active SMALLINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alias_domain (
    alias_domain VARCHAR(255) NOT NULL,
    target_domain VARCHAR(255) NOT NULL,
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0,
    active SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (alias_domain)
);
CREATE TABLE IF NOT EXISTS bm_console_ip_whitelist (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    ip_type SMALLINT NOT NULL DEFAULT 1,
    create_time INT NOT NULL DEFAULT 0,
    UNIQUE (ip)
);
ALTER TABLE domain ADD COLUMN IF NOT EXISTS urls TEXT[] DEFAULT '{}'::TEXT[];
ALTER TABLE domain ADD COLUMN IF NOT EXISTS hasbrandinfo SMALLINT DEFAULT 0;
ALTER TABLE domain ADD COLUMN IF NOT EXISTS current_usage BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mailbox ADD COLUMN IF NOT EXISTS used_quota BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mailbox ADD COLUMN IF NOT EXISTS quota_active SMALLINT NOT NULL DEFAULT 1;

-- SMTP relays -----------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bm_relay_config (
    id BIGSERIAL PRIMARY KEY,
    remark VARCHAR(255),
    rtype VARCHAR(30),
    relay_host VARCHAR(255) NOT NULL,
    relay_port VARCHAR(10) NOT NULL,
    auth_user VARCHAR(255) NOT NULL,
    auth_password VARCHAR(255) NOT NULL,
    ip VARCHAR(255),
    host VARCHAR(255),
    helo_name VARCHAR(255),
    skip_tls_verify SMALLINT DEFAULT 0,
    smtp_name VARCHAR(50),
    active SMALLINT NOT NULL DEFAULT 1,
    auth_method VARCHAR(20),
    create_time INT NOT NULL DEFAULT 0,
    update_time INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bm_relay_domain_mapping (
    id BIGSERIAL PRIMARY KEY,
    relay_id BIGINT NOT NULL,
    sender_domain VARCHAR(255) NOT NULL,
    create_time INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bm_domain_smtp_transport (
    id BIGSERIAL PRIMARY KEY,
    atype VARCHAR(50) NOT NULL DEFAULT 'relay',
    domain VARCHAR(255) NOT NULL,
    smtp_name VARCHAR(255) NOT NULL,
    UNIQUE(domain)
);
CREATE INDEX IF NOT EXISTS idx_domain_smtp_transport_domain ON bm_domain_smtp_transport(domain);
CREATE INDEX IF NOT EXISTS idx_domain_smtp_transport_atype ON bm_domain_smtp_transport(atype);
CREATE INDEX IF NOT EXISTS idx_domain_smtp_transport_domain_smtpName ON bm_domain_smtp_transport(domain, smtp_name);
CREATE INDEX IF NOT EXISTS idx_relay_domain_mapping_domain ON bm_relay_domain_mapping(sender_domain);
CREATE INDEX IF NOT EXISTS idx_relay_domain_mapping_relay_id ON bm_relay_domain_mapping(relay_id);

-- One mapping per relay and domain (Go removed duplicates first).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uk_relay_domain') THEN
        DELETE FROM bm_relay_domain_mapping
         WHERE id NOT IN (SELECT MIN(id) FROM bm_relay_domain_mapping GROUP BY relay_id, sender_domain);
        CREATE UNIQUE INDEX uk_relay_domain ON bm_relay_domain_mapping(relay_id, sender_domain);
    END IF;
END $$;

-- Relays of installs older than `bm_relay_config` (Go's migrateRelayData).
-- Never blocks start-up: an old table it cannot read is left alone.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
                WHERE table_schema = current_schema() AND table_name = 'bm_relay')
       AND NOT EXISTS (SELECT 1 FROM bm_relay_config) THEN
        BEGIN
            EXECUTE $migrate$
                WITH old AS (
                    SELECT *, left(COALESCE(NULLIF(smtp_name, ''),
                               'MigratedRelay_' || id || '_' || replace(relay_host, '.', '_')), 50) AS new_name
                      FROM bm_relay WHERE COALESCE(relay_host, '') <> ''
                ), moved AS (
                    INSERT INTO bm_relay_config (remark, rtype, relay_host, relay_port, auth_user,
                        auth_password, ip, host, helo_name, skip_tls_verify, smtp_name, active,
                        auth_method, create_time, update_time)
                    SELECT remark, rtype, relay_host, COALESCE(NULLIF(relay_port, ''), '25'),
                        COALESCE(auth_user, ''), COALESCE(auth_password, ''), ip, host, helo_name,
                        COALESCE(skip_tls_verify, 0), new_name, COALESCE(active, 1),
                        COALESCE(auth_method, 'LOGIN'), create_time, update_time
                      FROM old
                    RETURNING id, relay_host, smtp_name
                )
                INSERT INTO bm_relay_domain_mapping (relay_id, sender_domain, create_time)
                SELECT moved.id, old.sender_domain, old.create_time
                  FROM moved JOIN old ON old.relay_host = moved.relay_host AND old.new_name = moved.smtp_name
                 WHERE COALESCE(old.sender_domain, '') <> ''
                ON CONFLICT DO NOTHING
            $migrate$;
        EXCEPTION WHEN others THEN
            RAISE WARNING 'old relays (bm_relay) not moved: %', SQLERRM;
        END;
    END IF;
END $$;
