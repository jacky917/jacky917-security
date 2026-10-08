-- 第 3、4 階段：強制變更密碼、新的稽核事件（第 3、4 階段詳細設計 §3）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

ALTER TABLE app_user ADD COLUMN password_change_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE login_audit DROP CONSTRAINT ck_login_audit_event;

ALTER TABLE login_audit ADD CONSTRAINT ck_login_audit_event CHECK (event_type IN
    ('LOGIN', 'LOGOUT', 'TOKEN_REFRESH_REUSE', 'ACCOUNT_LOCKED', 'ACCOUNT_LINKED', 'ACCOUNT_UNLINKED', 'PASSWORD_CHANGED',
     'USER_REGISTERED', 'EMAIL_VERIFIED', 'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED', 'CONSENT_GRANTED',
     'CONSENT_REVOKED'));

ALTER TABLE admin_audit_log DROP CONSTRAINT ck_admin_audit_target;

ALTER TABLE admin_audit_log ADD CONSTRAINT ck_admin_audit_target CHECK (target_type IN
    ('USER', 'ROLE', 'PERMISSION', 'CLIENT', 'SCOPE', 'API_RESOURCE', 'SESSION', 'SIGNING_KEY'));
