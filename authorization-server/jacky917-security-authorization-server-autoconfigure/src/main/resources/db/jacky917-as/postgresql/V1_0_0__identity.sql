-- 身分：使用者、外部帳號、一次性 token（資料模型 §4）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE app_user (
    id                  VARCHAR(36)          PRIMARY KEY,
    username            VARCHAR(64),
    email               VARCHAR(255),
    email_verified      BOOLEAN       NOT NULL DEFAULT FALSE,
    password_hash       VARCHAR(255),
    display_name        VARCHAR(128),
    avatar_url          VARCHAR(1024),
    locale              VARCHAR(16),
    status              VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    failed_login_count  INT           NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ   NOT NULL,
    updated_at          TIMESTAMPTZ   NOT NULL,
    row_version         BIGINT        NOT NULL DEFAULT 0,
    CONSTRAINT ck_app_user_status   CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED', 'DELETED')),
    CONSTRAINT ck_app_user_username CHECK (username IS NULL OR length(username) BETWEEN 3 AND 64),
    CONSTRAINT ck_app_user_failures CHECK (failed_login_count >= 0)
);

CREATE UNIQUE INDEX ux_app_user_username ON app_user (LOWER(username)) WHERE username IS NOT NULL;

CREATE UNIQUE INDEX ux_app_user_email    ON app_user (LOWER(email))    WHERE email IS NOT NULL;

CREATE INDEX        ix_app_user_status   ON app_user (status)          WHERE status <> 'ACTIVE';

CREATE TABLE user_federated_identity (
    id               VARCHAR(36)          PRIMARY KEY,
    user_id          VARCHAR(36)          NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    provider         VARCHAR(32)   NOT NULL,
    provider_subject VARCHAR(255)  NOT NULL,
    email            VARCHAR(255),
    email_verified   BOOLEAN       NOT NULL DEFAULT FALSE,
    display_name     VARCHAR(128),
    avatar_url       VARCHAR(1024),
    raw_attributes   TEXT,
    linked_at        TIMESTAMPTZ   NOT NULL,
    last_login_at    TIMESTAMPTZ,
    CONSTRAINT ux_federated_provider_subject UNIQUE (provider, provider_subject),
    CONSTRAINT ux_federated_user_provider    UNIQUE (user_id, provider)
);

CREATE INDEX ix_federated_user ON user_federated_identity (user_id);

CREATE TABLE user_action_token (
    token_hash  CHAR(64)     PRIMARY KEY,
    user_id     VARCHAR(36)         NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    purpose     VARCHAR(32)  NOT NULL,
    payload     TEXT,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT ck_action_token_purpose CHECK (purpose IN ('PASSWORD_RESET', 'EMAIL_VERIFY', 'LINK_ACCOUNT')),
    CONSTRAINT ck_action_token_expiry  CHECK (expires_at > created_at)
);

CREATE INDEX ix_action_token_user    ON user_action_token (user_id, purpose) WHERE used_at IS NULL;

CREATE INDEX ix_action_token_expires ON user_action_token (expires_at);
