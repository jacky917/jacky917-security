-- 登入 Session、授權關聯、Refresh Token 歷史、Spring Session（資料模型 §7、§9）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE auth_session (
    session_id     VARCHAR(36)          PRIMARY KEY,
    user_id        VARCHAR(36)          NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    status         VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    login_method   VARCHAR(16)   NOT NULL,
    idp            VARCHAR(32)   NOT NULL DEFAULT 'local',
    amr            VARCHAR(64)   NOT NULL DEFAULT 'pwd',
    ip_address     VARCHAR(45),
    user_agent     VARCHAR(512),
    device_label   VARCHAR(128),
    created_at     TIMESTAMPTZ   NOT NULL,
    last_seen_at   TIMESTAMPTZ   NOT NULL,
    expires_at     TIMESTAMPTZ   NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  VARCHAR(32),
    CONSTRAINT ck_auth_session_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_auth_session_method CHECK (login_method IN ('PASSWORD', 'FEDERATED')),
    CONSTRAINT ck_auth_session_reason CHECK (revoke_reason IS NULL OR revoke_reason IN
        ('LOGOUT', 'LOGOUT_ALL', 'REUSE_DETECTED', 'ADMIN', 'PASSWORD_CHANGED', 'USER_DISABLED', 'EXPIRED')),
    CONSTRAINT ck_auth_session_revoked CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_auth_session_expiry  CHECK (expires_at > created_at)
);

CREATE INDEX ix_auth_session_user_active ON auth_session (user_id, last_seen_at DESC) WHERE status = 'ACTIVE';

CREATE INDEX ix_auth_session_expires     ON auth_session (expires_at) WHERE status = 'ACTIVE';

CREATE INDEX ix_auth_session_revoked_at  ON auth_session (revoked_at) WHERE status <> 'ACTIVE';

CREATE TABLE session_authorization (
    authorization_id     VARCHAR(100) PRIMARY KEY,
    session_id           VARCHAR(36)         NOT NULL REFERENCES auth_session(session_id) ON DELETE CASCADE,
    registered_client_id VARCHAR(100) NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL,
    CONSTRAINT fk_session_authz_authorization FOREIGN KEY (authorization_id)
        REFERENCES oauth2_authorization(id) ON DELETE CASCADE
);

CREATE INDEX ix_session_authz_session ON session_authorization (session_id);

CREATE TABLE refresh_token_history (
    token_hash           CHAR(64)      PRIMARY KEY,
    authorization_id     VARCHAR(100)  NOT NULL,
    session_id           VARCHAR(36),
    user_id              VARCHAR(36),
    registered_client_id VARCHAR(100)  NOT NULL,
    issued_at            TIMESTAMPTZ   NOT NULL,
    rotated_at           TIMESTAMPTZ   NOT NULL,
    expires_at           TIMESTAMPTZ   NOT NULL
);

CREATE INDEX ix_refresh_history_expires ON refresh_token_history (expires_at);

CREATE INDEX ix_refresh_history_session ON refresh_token_history (session_id);

CREATE TABLE SPRING_SESSION (
    PRIMARY_ID            CHAR(36)     NOT NULL,
    SESSION_ID            CHAR(36)     NOT NULL,
    CREATION_TIME         BIGINT       NOT NULL,
    LAST_ACCESS_TIME      BIGINT       NOT NULL,
    MAX_INACTIVE_INTERVAL INT          NOT NULL,
    EXPIRY_TIME           BIGINT       NOT NULL,
    PRINCIPAL_NAME        VARCHAR(100),
    CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);

CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);

CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);

CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);

CREATE TABLE SPRING_SESSION_ATTRIBUTES (
    SESSION_PRIMARY_ID CHAR(36)     NOT NULL,
    ATTRIBUTE_NAME     VARCHAR(200) NOT NULL,
    ATTRIBUTE_BYTES    BYTEA        NOT NULL,
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID)
        REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
);
