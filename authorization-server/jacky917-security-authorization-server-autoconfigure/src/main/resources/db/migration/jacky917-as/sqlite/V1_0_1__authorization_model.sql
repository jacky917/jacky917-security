-- 權限：角色、權限、API resource、scope（資料模型 §5）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

CREATE TABLE app_role (
    id          TEXT    NOT NULL PRIMARY KEY,
    code        TEXT    NOT NULL CONSTRAINT ux_app_role_code UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT,
    built_in    INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE app_permission (
    id          TEXT    NOT NULL PRIMARY KEY,
    code        TEXT    NOT NULL CONSTRAINT ux_app_permission_code UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT,
    built_in    INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE app_user_role (
    user_id    TEXT    NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id    TEXT    NOT NULL REFERENCES app_role(id) ON DELETE RESTRICT,
    granted_by TEXT    REFERENCES app_user(id) ON DELETE SET NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX ix_user_role_role ON app_user_role (role_id);

CREATE TABLE app_role_permission (
    role_id       TEXT NOT NULL REFERENCES app_role(id)       ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES app_permission(id) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX ix_role_permission_permission ON app_role_permission (permission_id);

CREATE TABLE api_resource (
    code        TEXT    NOT NULL PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE app_scope (
    code              TEXT    NOT NULL PRIMARY KEY,
    api_resource_code TEXT    REFERENCES api_resource(code) ON DELETE RESTRICT,
    display_name      TEXT    NOT NULL,
    description       TEXT,
    consent_required  INTEGER NOT NULL DEFAULT 1 CHECK (consent_required IN (0, 1)),
    built_in          INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    created_at        INTEGER NOT NULL
);

CREATE INDEX ix_app_scope_resource ON app_scope (api_resource_code);

CREATE TABLE app_scope_permission (
    scope_code    TEXT NOT NULL REFERENCES app_scope(code)      ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES app_permission(id) ON DELETE RESTRICT,
    PRIMARY KEY (scope_code, permission_id)
);

CREATE INDEX ix_scope_permission_permission ON app_scope_permission (permission_id);
