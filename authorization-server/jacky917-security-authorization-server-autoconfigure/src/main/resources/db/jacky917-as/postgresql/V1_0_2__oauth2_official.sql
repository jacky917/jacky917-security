-- Spring Security Authorization Server 官方表與自行新增的索引（資料模型 §6.1、§6.3、§6.4）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE oauth2_registered_client (
    id                            VARCHAR(100)  NOT NULL,
    client_id                     VARCHAR(100)  NOT NULL,
    client_id_issued_at           TIMESTAMPTZ   DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 VARCHAR(200)  DEFAULT NULL,
    client_secret_expires_at      TIMESTAMPTZ   DEFAULT NULL,
    client_name                   VARCHAR(200)  NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types     VARCHAR(1000) NOT NULL,
    redirect_uris                 VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris     VARCHAR(1000) DEFAULT NULL,
    scopes                        VARCHAR(1000) NOT NULL,
    client_settings               VARCHAR(2000) NOT NULL,
    token_settings                VARCHAR(2000) NOT NULL,
    PRIMARY KEY (id)
);

-- 自行新增（不改變欄位）：client_id 唯一，官方 repository 以 client_id 查詢
CREATE UNIQUE INDEX ux_registered_client_client_id ON oauth2_registered_client (client_id);

CREATE TABLE oauth2_authorization (
    id                            VARCHAR(100)  NOT NULL,
    registered_client_id          VARCHAR(100)  NOT NULL,
    principal_name                VARCHAR(200)  NOT NULL,
    authorization_grant_type      VARCHAR(100)  NOT NULL,
    authorized_scopes             VARCHAR(1000) DEFAULT NULL,
    attributes                    TEXT          DEFAULT NULL,
    state                         VARCHAR(500)  DEFAULT NULL,
    authorization_code_value      TEXT          DEFAULT NULL,
    authorization_code_issued_at  TIMESTAMPTZ   DEFAULT NULL,
    authorization_code_expires_at TIMESTAMPTZ   DEFAULT NULL,
    authorization_code_metadata   TEXT          DEFAULT NULL,
    access_token_value            TEXT          DEFAULT NULL,
    access_token_issued_at        TIMESTAMPTZ   DEFAULT NULL,
    access_token_expires_at       TIMESTAMPTZ   DEFAULT NULL,
    access_token_metadata         TEXT          DEFAULT NULL,
    access_token_type             VARCHAR(100)  DEFAULT NULL,
    access_token_scopes           VARCHAR(1000) DEFAULT NULL,
    oidc_id_token_value           TEXT          DEFAULT NULL,
    oidc_id_token_issued_at       TIMESTAMPTZ   DEFAULT NULL,
    oidc_id_token_expires_at      TIMESTAMPTZ   DEFAULT NULL,
    oidc_id_token_metadata        TEXT          DEFAULT NULL,
    refresh_token_value           TEXT          DEFAULT NULL,
    refresh_token_issued_at       TIMESTAMPTZ   DEFAULT NULL,
    refresh_token_expires_at      TIMESTAMPTZ   DEFAULT NULL,
    refresh_token_metadata        TEXT          DEFAULT NULL,
    user_code_value               TEXT          DEFAULT NULL,
    user_code_issued_at           TIMESTAMPTZ   DEFAULT NULL,
    user_code_expires_at          TIMESTAMPTZ   DEFAULT NULL,
    user_code_metadata            TEXT          DEFAULT NULL,
    device_code_value             TEXT          DEFAULT NULL,
    device_code_issued_at         TIMESTAMPTZ   DEFAULT NULL,
    device_code_expires_at        TIMESTAMPTZ   DEFAULT NULL,
    device_code_metadata          TEXT          DEFAULT NULL,
    PRIMARY KEY (id)
);

-- 以 token 值查詢（換 Token、刷新、撤銷、內省、登出時的 id_token_hint）
-- token 值是長字串、只做等值比對，使用 HASH 索引（體積小；PostgreSQL 10 起已寫入 WAL）
CREATE INDEX ix_oauth2_authz_state        ON oauth2_authorization USING HASH (state);

CREATE INDEX ix_oauth2_authz_code         ON oauth2_authorization USING HASH (authorization_code_value);

CREATE INDEX ix_oauth2_authz_access       ON oauth2_authorization USING HASH (access_token_value);

CREATE INDEX ix_oauth2_authz_refresh      ON oauth2_authorization USING HASH (refresh_token_value);

CREATE INDEX ix_oauth2_authz_id_token     ON oauth2_authorization USING HASH (oidc_id_token_value);

-- 依使用者撤銷（登出所有裝置、停權、改密碼）
CREATE INDEX ix_oauth2_authz_principal    ON oauth2_authorization (principal_name, registered_client_id);

-- 清理排程（§14）
CREATE INDEX ix_oauth2_authz_refresh_exp  ON oauth2_authorization (refresh_token_expires_at);

CREATE INDEX ix_oauth2_authz_access_exp   ON oauth2_authorization (access_token_expires_at);

CREATE INDEX ix_oauth2_authz_code_exp     ON oauth2_authorization (authorization_code_expires_at);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- 自行新增：使用者在帳號設定頁列出、撤回已授權的第三方應用
CREATE INDEX ix_oauth2_consent_principal ON oauth2_authorization_consent (principal_name);
