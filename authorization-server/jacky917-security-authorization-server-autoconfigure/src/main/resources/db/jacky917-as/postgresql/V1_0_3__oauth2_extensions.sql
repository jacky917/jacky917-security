-- Client 擴充資料（資料模型 §6.2）
-- PostgreSQL 16 以上。資料表、欄位、索引與具名約束的名稱必須與 sqlite/ 中的同名檔案一致。

CREATE TABLE client_profile (
    registered_client_id VARCHAR(100)  PRIMARY KEY,
    trust_level          VARCHAR(16)   NOT NULL,
    display_name         VARCHAR(128)  NOT NULL,
    description          TEXT,
    logo_url             VARCHAR(1024),
    homepage_url         VARCHAR(1024),
    privacy_policy_url   VARCHAR(1024),
    terms_url            VARCHAR(1024),
    owner_user_id        VARCHAR(36)          REFERENCES app_user(id) ON DELETE SET NULL,
    status               VARCHAR(16)   NOT NULL DEFAULT 'ACTIVE',
    created_at           TIMESTAMPTZ   NOT NULL,
    updated_at           TIMESTAMPTZ   NOT NULL,
    CONSTRAINT fk_client_profile_client FOREIGN KEY (registered_client_id)
        REFERENCES oauth2_registered_client(id) ON DELETE CASCADE,
    CONSTRAINT ck_client_profile_trust  CHECK (trust_level IN ('FIRST_PARTY', 'THIRD_PARTY')),
    CONSTRAINT ck_client_profile_status CHECK (status IN ('PENDING_REVIEW', 'ACTIVE', 'SUSPENDED')),
    CONSTRAINT ck_client_profile_third_party_policy
        CHECK (trust_level = 'FIRST_PARTY' OR privacy_policy_url IS NOT NULL)
);

CREATE INDEX ix_client_profile_owner ON client_profile (owner_user_id);
