-- 權限：角色、權限、API resource、scope（資料模型 §5）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE app_role (
    id          VARCHAR(36)          PRIMARY KEY,
    code        VARCHAR(64)   NOT NULL,
    name        VARCHAR(128)  NOT NULL,
    description TEXT,
    built_in    BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ   NOT NULL,
    updated_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT ux_app_role_code UNIQUE (code)
);

CREATE TABLE app_permission (
    id          VARCHAR(36)          PRIMARY KEY,
    code        VARCHAR(128)  NOT NULL,
    name        VARCHAR(128)  NOT NULL,
    description TEXT,
    built_in    BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ   NOT NULL,
    updated_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT ux_app_permission_code UNIQUE (code)
);

CREATE TABLE app_user_role (
    user_id    VARCHAR(36)         NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id    VARCHAR(36)         NOT NULL REFERENCES app_role(id) ON DELETE RESTRICT,
    granted_by VARCHAR(36)         REFERENCES app_user(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ  NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX ix_user_role_role ON app_user_role (role_id);

CREATE TABLE app_role_permission (
    role_id       VARCHAR(36) NOT NULL REFERENCES app_role(id)       ON DELETE CASCADE,
    permission_id VARCHAR(36) NOT NULL REFERENCES app_permission(id) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX ix_role_permission_permission ON app_role_permission (permission_id);

CREATE TABLE api_resource (
    code        VARCHAR(64)   PRIMARY KEY,
    name        VARCHAR(128)  NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ   NOT NULL
);

CREATE TABLE app_scope (
    code              VARCHAR(128)  PRIMARY KEY,
    api_resource_code VARCHAR(64)   REFERENCES api_resource(code) ON DELETE RESTRICT,
    display_name      VARCHAR(128)  NOT NULL,
    description       TEXT,
    consent_required  BOOLEAN       NOT NULL DEFAULT TRUE,
    built_in          BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ   NOT NULL
);

CREATE INDEX ix_app_scope_resource ON app_scope (api_resource_code);

CREATE TABLE app_scope_permission (
    scope_code    VARCHAR(128) NOT NULL REFERENCES app_scope(code)      ON DELETE CASCADE,
    permission_id VARCHAR(36)         NOT NULL REFERENCES app_permission(id) ON DELETE RESTRICT,
    PRIMARY KEY (scope_code, permission_id)
);

CREATE INDEX ix_scope_permission_permission ON app_scope_permission (permission_id);
