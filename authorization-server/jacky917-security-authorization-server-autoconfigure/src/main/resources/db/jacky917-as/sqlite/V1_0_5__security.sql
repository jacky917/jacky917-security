-- 簽章金鑰、稽核、排程鎖（資料模型 §8）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

CREATE TABLE signing_key (
    kid                   TEXT    NOT NULL PRIMARY KEY,
    algorithm             TEXT    NOT NULL DEFAULT 'RS256' CONSTRAINT ck_signing_key_algorithm CHECK (algorithm IN ('RS256', 'ES256')),
    key_size              INTEGER NOT NULL DEFAULT 3072,
    public_key            TEXT    NOT NULL,
    private_key_encrypted TEXT    NOT NULL,
    encryption_key_id     TEXT    NOT NULL,
    status                TEXT    NOT NULL CONSTRAINT ck_signing_key_status CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRING', 'RETIRED')),
    created_at            INTEGER NOT NULL,
    activated_at          INTEGER,
    retiring_at           INTEGER,
    retired_at            INTEGER
);

CREATE UNIQUE INDEX ux_signing_key_single_active ON signing_key (status) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX ux_signing_key_single_next   ON signing_key (status) WHERE status = 'NEXT';

CREATE TABLE login_audit (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at          INTEGER NOT NULL,
    event_type           TEXT    NOT NULL CONSTRAINT ck_login_audit_event CHECK (event_type IN
        ('LOGIN', 'LOGOUT', 'TOKEN_REFRESH_REUSE', 'ACCOUNT_LOCKED', 'ACCOUNT_LINKED', 'ACCOUNT_UNLINKED', 'PASSWORD_CHANGED')),
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

CREATE INDEX ix_login_audit_ip_time   ON login_audit (ip_address, occurred_at DESC);

CREATE INDEX ix_login_audit_user_time ON login_audit (user_id, occurred_at DESC);

CREATE INDEX ix_login_audit_time      ON login_audit (occurred_at);

CREATE TABLE admin_audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at      INTEGER NOT NULL,
    operator_user_id TEXT,
    operator_client  TEXT,
    action           TEXT    NOT NULL,
    target_type      TEXT    NOT NULL CONSTRAINT ck_admin_audit_target CHECK (target_type IN ('USER', 'ROLE', 'PERMISSION', 'CLIENT', 'SCOPE', 'SESSION', 'SIGNING_KEY')),
    target_id        TEXT,
    before_value     TEXT    CHECK (before_value IS NULL OR json_valid(before_value)),
    after_value      TEXT    CHECK (after_value IS NULL OR json_valid(after_value)),
    ip_address       TEXT
);

CREATE INDEX ix_admin_audit_target   ON admin_audit_log (target_type, target_id, occurred_at DESC);

CREATE INDEX ix_admin_audit_operator ON admin_audit_log (operator_user_id, occurred_at DESC);

CREATE TABLE shedlock (
    name       TEXT    NOT NULL PRIMARY KEY,
    lock_until INTEGER NOT NULL,
    locked_at  INTEGER NOT NULL,
    locked_by  TEXT    NOT NULL
);
