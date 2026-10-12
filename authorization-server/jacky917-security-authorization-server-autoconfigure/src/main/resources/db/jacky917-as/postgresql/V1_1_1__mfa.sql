-- 兩步驟驗證（第 3、4 階段詳細設計 §3、§7、D31）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE user_mfa_totp (
    user_id           VARCHAR(36)  PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    secret_encrypted  TEXT         NOT NULL,
    encryption_key_id VARCHAR(64)  NOT NULL,
    last_used_step    BIGINT       NOT NULL DEFAULT 0,
    enabled_at        TIMESTAMPTZ  NOT NULL
);

CREATE TABLE user_recovery_code (
    user_id    VARCHAR(36)  NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    code_hash  CHAR(64)     NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
