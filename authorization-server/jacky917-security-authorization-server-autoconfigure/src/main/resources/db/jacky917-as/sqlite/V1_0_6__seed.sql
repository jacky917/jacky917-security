-- 內建資料（資料模型 §12）：AS 自身管理功能的角色與權限、OIDC scope、共用的 API resource。
-- ID 為固定值，讓所有安裝的內建資料相同。業務權限（例如 order:read）由各專案自行新增。

INSERT INTO api_resource (code, name, description, created_at) VALUES
    ('jacky917-api', 'jacky917 API', '第一版所有 Resource Server 共用的 audience', 1791417600000);

INSERT INTO app_role (id, code, name, description, built_in, created_at, updated_at) VALUES
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', 'AS_ADMIN', 'AS 管理員', '管理使用者、角色、client 與稽核紀錄', 1, 1791417600000, 1791417600000),
    ('b8f31a77-1793-55f2-b6b0-398a5e28517d', 'AS_SUPPORT', 'AS 客服', '查詢使用者、強制登出、查詢稽核紀錄', 1, 1791417600000, 1791417600000),
    ('b3100388-a4be-5f33-a3c8-bc974bcc5ce6', 'USER', '使用者', '所有使用者預設擁有的角色', 1, 1791417600000, 1791417600000);

INSERT INTO app_permission (id, code, name, description, built_in, created_at, updated_at) VALUES
    ('61a6d564-bad1-58d6-99b7-e20ce3999a2f', 'as:user:read', '查詢使用者', NULL, 1, 1791417600000, 1791417600000),
    ('5cff0f57-fc79-5970-bb39-5c5b4971deb2', 'as:user:write', '管理使用者', NULL, 1, 1791417600000, 1791417600000),
    ('bce18227-fd45-5183-84a4-a612b483dc42', 'as:role:read', '查詢角色', NULL, 1, 1791417600000, 1791417600000),
    ('f5e1f846-8b11-58a3-82f2-f7aa95de7b4b', 'as:role:write', '管理角色', NULL, 1, 1791417600000, 1791417600000),
    ('ca868a81-0562-5452-9eeb-77bb92d416a5', 'as:client:read', '查詢 client', NULL, 1, 1791417600000, 1791417600000),
    ('56b92a3e-63cd-5393-887b-f496b291d035', 'as:client:write', '管理 client', NULL, 1, 1791417600000, 1791417600000),
    ('b6663993-1d1d-5563-b906-11310813bb02', 'as:session:revoke', '撤銷登入 Session', NULL, 1, 1791417600000, 1791417600000),
    ('0c8c6b1c-360a-53a0-9ae3-79bff5a79db7', 'as:audit:read', '查詢稽核紀錄', NULL, 1, 1791417600000, 1791417600000);

INSERT INTO app_role_permission (role_id, permission_id) VALUES
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', '61a6d564-bad1-58d6-99b7-e20ce3999a2f'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', '5cff0f57-fc79-5970-bb39-5c5b4971deb2'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', 'bce18227-fd45-5183-84a4-a612b483dc42'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', 'f5e1f846-8b11-58a3-82f2-f7aa95de7b4b'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', 'ca868a81-0562-5452-9eeb-77bb92d416a5'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', '56b92a3e-63cd-5393-887b-f496b291d035'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', 'b6663993-1d1d-5563-b906-11310813bb02'),
    ('3a9111ad-8c00-5a67-8347-6a803ea434b3', '0c8c6b1c-360a-53a0-9ae3-79bff5a79db7'),
    ('b8f31a77-1793-55f2-b6b0-398a5e28517d', '61a6d564-bad1-58d6-99b7-e20ce3999a2f'),
    ('b8f31a77-1793-55f2-b6b0-398a5e28517d', 'b6663993-1d1d-5563-b906-11310813bb02'),
    ('b8f31a77-1793-55f2-b6b0-398a5e28517d', '0c8c6b1c-360a-53a0-9ae3-79bff5a79db7');

INSERT INTO app_scope (code, api_resource_code, display_name, description, consent_required, built_in, created_at) VALUES
    ('openid', NULL, 'OpenID', 'OIDC 必要的 scope', 0, 1, 1791417600000),
    ('profile', NULL, '基本資料', '姓名、頭像、語系', 1, 1, 1791417600000),
    ('email', NULL, 'Email', 'Email 與是否已驗證', 1, 1, 1791417600000);
