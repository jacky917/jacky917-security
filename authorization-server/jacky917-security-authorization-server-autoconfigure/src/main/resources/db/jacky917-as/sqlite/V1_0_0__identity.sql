-- 身分：使用者、外部帳號、一次性 token（資料模型 §4）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

CREATE TABLE app_user (
    id                  TEXT     NOT NULL PRIMARY KEY CHECK (length(id) = 36),
    username            TEXT     CONSTRAINT ck_app_user_username CHECK (username IS NULL OR length(username) BETWEEN 3 AND 64),
    email               TEXT     CHECK (email IS NULL OR length(email) <= 255),
    email_verified      INTEGER  NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    password_hash       TEXT,
    display_name        TEXT,
    avatar_url          TEXT,
    locale              TEXT,
    status              TEXT     NOT NULL DEFAULT 'ACTIVE' CONSTRAINT ck_app_user_status CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'DELETED')),
    failed_login_count  INTEGER  NOT NULL DEFAULT 0 CONSTRAINT ck_app_user_failures CHECK (failed_login_count >= 0),
    locked_until        INTEGER,
    password_changed_at INTEGER,
    last_login_at       INTEGER,
    created_at          INTEGER  NOT NULL,
    updated_at          INTEGER  NOT NULL,
    row_version         INTEGER  NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX ux_app_user_username ON app_user (lower(username)) WHERE username IS NOT NULL;

CREATE UNIQUE INDEX ux_app_user_email    ON app_user (lower(email))    WHERE email IS NOT NULL;

CREATE INDEX        ix_app_user_status   ON app_user (status)          WHERE status <> 'ACTIVE';

CREATE TABLE user_federated_identity (
    id               TEXT    NOT NULL PRIMARY KEY,
    user_id          TEXT    NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    provider         TEXT    NOT NULL,
    provider_subject TEXT    NOT NULL,
    email            TEXT,
    email_verified   INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    display_name     TEXT,
    avatar_url       TEXT,
    raw_attributes   TEXT    CHECK (raw_attributes IS NULL OR json_valid(raw_attributes)),
    linked_at        INTEGER NOT NULL,
    last_login_at    INTEGER,
    CONSTRAINT ux_federated_provider_subject UNIQUE (provider, provider_subject),
    CONSTRAINT ux_federated_user_provider    UNIQUE (user_id, provider)
);

CREATE INDEX ix_federated_user ON user_federated_identity (user_id);

CREATE TABLE user_action_token (
    token_hash TEXT    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 64),
    user_id    TEXT    NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    purpose    TEXT    NOT NULL CONSTRAINT ck_action_token_purpose CHECK (purpose IN ('PASSWORD_RESET', 'EMAIL_VERIFY', 'LINK_ACCOUNT')),
    payload    TEXT    CHECK (payload IS NULL OR json_valid(payload)),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL,
    CONSTRAINT ck_action_token_expiry CHECK (expires_at > created_at)
);

CREATE INDEX ix_action_token_user    ON user_action_token (user_id, purpose) WHERE used_at IS NULL;

CREATE INDEX ix_action_token_expires ON user_action_token (expires_at);
