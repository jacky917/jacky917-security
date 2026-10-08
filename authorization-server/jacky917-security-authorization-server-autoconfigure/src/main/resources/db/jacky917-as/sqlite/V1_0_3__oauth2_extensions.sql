-- Client 擴充資料（資料模型 §6.2）
-- SQLite 方言（資料模型 §17）。資料表、欄位、索引與具名約束的名稱必須與 postgresql/ 中的同名檔案一致。

CREATE TABLE client_profile (
    registered_client_id TEXT    NOT NULL PRIMARY KEY CONSTRAINT fk_client_profile_client REFERENCES oauth2_registered_client(id) ON DELETE CASCADE,
    trust_level          TEXT    NOT NULL CONSTRAINT ck_client_profile_trust CHECK (trust_level IN ('FIRST_PARTY', 'THIRD_PARTY')),
    display_name         TEXT    NOT NULL,
    description          TEXT,
    logo_url             TEXT,
    homepage_url         TEXT,
    privacy_policy_url   TEXT,
    terms_url            TEXT,
    owner_user_id        TEXT    REFERENCES app_user(id) ON DELETE SET NULL,
    status               TEXT    NOT NULL DEFAULT 'ACTIVE' CONSTRAINT ck_client_profile_status CHECK (status IN ('PENDING_REVIEW', 'ACTIVE', 'SUSPENDED')),
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    CONSTRAINT ck_client_profile_third_party_policy CHECK (trust_level = 'FIRST_PARTY' OR privacy_policy_url IS NOT NULL)
);

CREATE INDEX ix_client_profile_owner ON client_profile (owner_user_id);
