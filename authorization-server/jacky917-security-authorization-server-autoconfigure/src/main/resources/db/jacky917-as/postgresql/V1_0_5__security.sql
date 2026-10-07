-- 簽章金鑰、稽核、排程鎖（資料模型 §8）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE signing_key (
    kid                   VARCHAR(64)  PRIMARY KEY,
    algorithm             VARCHAR(16)  NOT NULL DEFAULT 'RS256',
    key_size              INT          NOT NULL DEFAULT 3072,
    public_key            TEXT         NOT NULL,
    private_key_encrypted TEXT         NOT NULL,
    encryption_key_id     VARCHAR(64)  NOT NULL,
    status                VARCHAR(16)  NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL,
    activated_at          TIMESTAMPTZ,
    retiring_at           TIMESTAMPTZ,
    retired_at            TIMESTAMPTZ,
    CONSTRAINT ck_signing_key_status    CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRING', 'RETIRED')),
    CONSTRAINT ck_signing_key_algorithm CHECK (algorithm IN ('RS256', 'ES256'))
);

CREATE UNIQUE INDEX ux_signing_key_single_active ON signing_key (status) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX ux_signing_key_single_next   ON signing_key (status) WHERE status = 'NEXT';

CREATE TABLE login_audit (
    id                   BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at          TIMESTAMPTZ   NOT NULL,
    event_type           VARCHAR(32)   NOT NULL,
    user_id              VARCHAR(36)          REFERENCES app_user(id) ON DELETE SET NULL,
    username_attempted   VARCHAR(255),
    login_method         VARCHAR(16),
    idp                  VARCHAR(32),
    registered_client_id VARCHAR(100),
    session_id           VARCHAR(36),
    success              BOOLEAN       NOT NULL,
    failure_reason       VARCHAR(32),
    ip_address           VARCHAR(45),
    user_agent           VARCHAR(512),
    CONSTRAINT ck_login_audit_event CHECK (event_type IN
        ('LOGIN', 'LOGOUT', 'TOKEN_REFRESH_REUSE', 'ACCOUNT_LOCKED', 'ACCOUNT_LINKED', 'ACCOUNT_UNLINKED', 'PASSWORD_CHANGED'))
);

CREATE INDEX ix_login_audit_ip_time   ON login_audit (ip_address, occurred_at DESC);

CREATE INDEX ix_login_audit_user_time ON login_audit (user_id, occurred_at DESC);

CREATE INDEX ix_login_audit_time ON login_audit USING BRIN (occurred_at);

CREATE TABLE admin_audit_log (
    id               BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at      TIMESTAMPTZ   NOT NULL,
    operator_user_id VARCHAR(36),
    operator_client  VARCHAR(100),
    action           VARCHAR(64)   NOT NULL,
    target_type      VARCHAR(32)   NOT NULL,
    target_id        VARCHAR(100),
    before_value     TEXT,
    after_value      TEXT,
    ip_address       VARCHAR(45),
    CONSTRAINT ck_admin_audit_target CHECK (target_type IN ('USER', 'ROLE', 'PERMISSION', 'CLIENT', 'SCOPE', 'SESSION', 'SIGNING_KEY'))
);

CREATE INDEX ix_admin_audit_target   ON admin_audit_log (target_type, target_id, occurred_at DESC);

CREATE INDEX ix_admin_audit_operator ON admin_audit_log (operator_user_id, occurred_at DESC);

CREATE TABLE shedlock (
    name       VARCHAR(64)  PRIMARY KEY,
    lock_until TIMESTAMPTZ  NOT NULL,
    locked_at  TIMESTAMPTZ  NOT NULL,
    locked_by  VARCHAR(255) NOT NULL
);
