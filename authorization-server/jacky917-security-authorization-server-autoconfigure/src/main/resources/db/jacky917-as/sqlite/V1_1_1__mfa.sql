-- 兩步驟驗證（第 3、4 階段詳細設計 §3、§7、D31）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

CREATE TABLE user_mfa_totp (
    user_id           TEXT    NOT NULL PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    secret_encrypted  TEXT    NOT NULL,
    encryption_key_id TEXT    NOT NULL,
    last_used_step    INTEGER NOT NULL DEFAULT 0,
    enabled_at        INTEGER NOT NULL
);

CREATE TABLE user_recovery_code (
    user_id    TEXT    NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL CHECK (length(code_hash) = 64),
    used_at    INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
