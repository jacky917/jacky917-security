# 資料表設計（Database Schema）

本文件提供 Authorization Server 的參考資料表設計，用於支援：

- 多裝置 Session 管理（以 `sid` 為核心）
- Refresh Token Rotation（每次刷新都換發新 RT）
- Reuse Detection（舊 RT 被重用時，撤銷整個 family）

> 本專案核心為 Resource Server；以下屬於架構設計參考，建議在獨立 Auth Server 實作。

---

## 設計原則

1. **Refresh Token 僅存 Hash，不存明文**
2. **Session 與 Token 解耦**：`auth_session` 管裝置/登入態，`refresh_token` 管輪換鏈
3. **用 `family_id` 管理一條 RT 鏈**：便於一次撤銷整個家族
4. **預設保守**：偵測重用即整鏈撤銷，並要求重新登入

---

## 1) `auth_session`（會話主檔）

### PostgreSQL DDL

```sql
CREATE TABLE auth_session (
    session_id           UUID PRIMARY KEY,                        -- 對應 JWT sid
    user_id              VARCHAR(128) NOT NULL,                   -- 使用者識別（可對應 sub）
    status               VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE / REVOKED / EXPIRED
    device_name          VARCHAR(128),                            -- 裝置名稱（可選）
    user_agent           TEXT,                                    -- UA（可選）
    ip_address           VARCHAR(45),                             -- IPv4/IPv6（可選）
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at           TIMESTAMPTZ,
    revoke_reason        VARCHAR(64)
);

CREATE INDEX idx_auth_session_user_id ON auth_session (user_id);
CREATE INDEX idx_auth_session_status ON auth_session (status);
CREATE INDEX idx_auth_session_last_seen_at ON auth_session (last_seen_at);
```

### 欄位說明

| 欄位 | 用途說明 |
|---|---|
| `session_id` | 會話唯一 ID，建議用 UUID，並寫入 Access Token 的 `sid`。 |
| `user_id` | 使用者主鍵或業務識別碼。 |
| `status` | 會話狀態；單裝置踢除時可改為 `REVOKED`。 |
| `device_name` | 顯示給使用者的裝置名稱。 |
| `user_agent` | 客戶端 UA，供風險分析與稽核。 |
| `ip_address` | 來源 IP。 |
| `created_at` | 會話建立時間。 |
| `last_seen_at` | 最近活動時間（可於 refresh 成功時更新）。 |
| `revoked_at` | 會話撤銷時間。 |
| `revoke_reason` | 撤銷原因（手動登出、reuse_detected 等）。 |

---

## 2) `refresh_token`（刷新令牌）

### PostgreSQL DDL

```sql
CREATE TABLE refresh_token (
    token_id             UUID PRIMARY KEY,                        -- 每筆 RT 紀錄 ID
    token_hash           CHAR(64) NOT NULL UNIQUE,                -- SHA-256(Refresh Token)
    family_id            UUID NOT NULL,                           -- 同一登入鏈家族 ID
    session_id           UUID NOT NULL REFERENCES auth_session(session_id) ON DELETE CASCADE,
    user_id              VARCHAR(128) NOT NULL,                   -- 冗餘欄位，提升查詢效率
    parent_token_id      UUID REFERENCES refresh_token(token_id), -- 上一代 RT（rotation 鏈）
    replaced_by_token_id UUID REFERENCES refresh_token(token_id), -- 下一代 RT
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,
    consumed_at          TIMESTAMPTZ,                             -- 首次被兌換時間
    revoked_at           TIMESTAMPTZ,
    revoke_reason        VARCHAR(64),
    created_by_ip        VARCHAR(45),
    created_by_ua        TEXT
);

-- 強烈建議索引
CREATE INDEX idx_refresh_token_session_id ON refresh_token (session_id);
CREATE INDEX idx_refresh_token_family_id ON refresh_token (family_id);
CREATE INDEX idx_refresh_token_user_id ON refresh_token (user_id);
CREATE INDEX idx_refresh_token_expires_at ON refresh_token (expires_at);
CREATE INDEX idx_refresh_token_revoked_at ON refresh_token (revoked_at);
CREATE INDEX idx_refresh_token_consumed_at ON refresh_token (consumed_at);
```

### 欄位說明

| 欄位 | 用途說明 |
|---|---|
| `token_id` | RT 紀錄主鍵。 |
| `token_hash` | Refresh Token 雜湊值；資料庫不可保存明文 RT。 |
| `family_id` | 一次登入流程的 RT 家族識別；發生重用時可整族撤銷。 |
| `session_id` | 關聯到 `auth_session.session_id`，對應單裝置會話。 |
| `user_id` | 冗餘使用者識別，便於統計與全域撤銷查詢。 |
| `parent_token_id` | 前一代 RT，形成 rotation 鏈。 |
| `replaced_by_token_id` | 由哪一顆新 RT 取代。 |
| `issued_at` | 簽發時間。 |
| `expires_at` | 到期時間。 |
| `consumed_at` | 第一次被用來換 token 的時間。 |
| `revoked_at` | 被撤銷時間。 |
| `revoke_reason` | 撤銷原因（logout / reuse_detected / admin_force_logout）。 |
| `created_by_ip` | 建立 RT 時的來源 IP。 |
| `created_by_ua` | 建立 RT 時的裝置資訊。 |

---

## Reuse Detection 判斷規則（資料層）

當收到 Refresh Token（記為 RTx）：

1. 以 `token_hash` 查詢 `refresh_token`
2. 若查無資料、已過期、`revoked_at` 不為空 -> 直接拒絕
3. 若 `consumed_at` 已有值或 `replaced_by_token_id` 已有值 -> 視為 **reuse**
4. 觸發：
   - `UPDATE refresh_token SET revoked_at = NOW(), revoke_reason = 'reuse_detected' WHERE family_id = :familyId AND revoked_at IS NULL;`
   - `UPDATE auth_session SET status = 'REVOKED', revoked_at = NOW(), revoke_reason = 'reuse_detected' WHERE session_id = :sessionId;`

此策略可避免舊 RT 被重放後持續濫用。
