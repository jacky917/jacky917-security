-- 第 3、4 階段：強制變更密碼、新的稽核事件（第 3、4 階段詳細設計 §3）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

ALTER TABLE app_user ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0
    CHECK (password_change_required IN (0, 1));

-- SQLite 無法修改約束：重建 login_audit（沒有其他資料表參照它）
CREATE TABLE login_audit_v2 (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at          INTEGER NOT NULL,
    event_type           TEXT    NOT NULL CONSTRAINT ck_login_audit_event CHECK (event_type IN
        ('LOGIN', 'LOGOUT', 'TOKEN_REFRESH_REUSE', 'ACCOUNT_LOCKED', 'ACCOUNT_LINKED', 'ACCOUNT_UNLINKED', 'PASSWORD_CHANGED',
         'USER_REGISTERED', 'EMAIL_VERIFIED', 'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED', 'CONSENT_GRANTED',
         'CONSENT_REVOKED')),
    user_id              TEXT    REFERENCES app_user(id) ON DELETE SET NULL,
    username_attempted   TEXT,
    login_method         TEXT,
    idp                  TEXT,
    registered_client_id TEXT,
    session_id           TEXT,
    success              INTEGER NOT NULL CHECK (success IN (0, 1)),
    failure_reason       TEXT,
    ip_address           TEXT,
    user_agent           TEXT
);

INSERT INTO login_audit_v2 (id, occurred_at, event_type, user_id, username_attempted, login_method, idp,
                            registered_client_id, session_id, success, failure_reason, ip_address, user_agent)
SELECT id, occurred_at, event_type, user_id, username_attempted, login_method, idp, registered_client_id, session_id,
       success, failure_reason, ip_address, user_agent
FROM login_audit;

DROP TABLE login_audit;

ALTER TABLE login_audit_v2 RENAME TO login_audit;

CREATE INDEX ix_login_audit_ip_time   ON login_audit (ip_address, occurred_at DESC);

CREATE INDEX ix_login_audit_user_time ON login_audit (user_id, occurred_at DESC);

CREATE INDEX ix_login_audit_time      ON login_audit (occurred_at);

-- 同上：重建 admin_audit_log，加入 API_RESOURCE
CREATE TABLE admin_audit_log_v2 (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at      INTEGER NOT NULL,
    operator_user_id TEXT,
    operator_client  TEXT,
    action           TEXT    NOT NULL,
    target_type      TEXT    NOT NULL CONSTRAINT ck_admin_audit_target CHECK (target_type IN
        ('USER', 'ROLE', 'PERMISSION', 'CLIENT', 'SCOPE', 'API_RESOURCE', 'SESSION', 'SIGNING_KEY')),
    target_id        TEXT,
    before_value     TEXT    CHECK (before_value IS NULL OR json_valid(before_value)),
    after_value      TEXT    CHECK (after_value IS NULL OR json_valid(after_value)),
    ip_address       TEXT
);

INSERT INTO admin_audit_log_v2 (id, occurred_at, operator_user_id, operator_client, action, target_type, target_id,
                                before_value, after_value, ip_address)
SELECT id, occurred_at, operator_user_id, operator_client, action, target_type, target_id, before_value, after_value,
       ip_address
FROM admin_audit_log;

DROP TABLE admin_audit_log;

ALTER TABLE admin_audit_log_v2 RENAME TO admin_audit_log;

CREATE INDEX ix_admin_audit_target   ON admin_audit_log (target_type, target_id, occurred_at DESC);

CREATE INDEX ix_admin_audit_operator ON admin_audit_log (operator_user_id, occurred_at DESC);
