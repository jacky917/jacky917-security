# JWT Claims 契約

本文件定義了此安全框架所期望的 JWT (JSON Web Token) Claims 結構。所有傳入的 JWT 都應遵循此契約，以確保權限系統能正確解析與運作。

## 標準 Claims

| Claim | 名稱 (Full Name) | 說明 | 格式 | 強制性 |
|-------|--------------------|------|------|----------|
| `iss` | Issuer | 簽發者。必須與 Resource Server 設定的信任簽發者匹配。 | String (URI) | **必要** |
| `sub` | Subject | 主體，通常是使用者的唯一識別碼（如 UUID）。 | String | **必要** |
| `aud` | Audience | 受眾。必須包含此 Resource Server 的識別碼。 | Array of String | **必要** |
| `exp` | Expiration Time | 過期時間。Token 在此時間之後無效。 | NumericDate (Unix Timestamp) | **必要** |
| `nbf` | Not Before | 生效時間。Token 在此時間之前無效。 | NumericDate (Unix Timestamp) | 建議 |
| `iat` | Issued At | 簽發時間。 | NumericDate (Unix Timestamp) | 建議 |
| `jti` | JWT ID | JWT 的唯一識別碼，可用於防止重放攻擊。 | String | 建議 |

## 自訂 Claims (權限相關)

為了實現靈活的授權模型，本框架支援從多個自訂 claims 中提取權限資訊。預設的處理順序與邏輯如下：

| Claim | 型態 | 處理邏輯 | 範例 |
|---|---|---|---|
| `roles` | `Array<String>` 或 `String`（逗號分隔） | 每個角色字串會被加上 `ROLE_` 前綴，並轉換為 `GrantedAuthority`。 | `["ADMIN", "USER"]` 或 `"ADMIN,USER"` -> `ROLE_ADMIN`, `ROLE_USER` |
| `permissions`| `Array<String>` 或 `String`（逗號分隔） | 每個權限字串會被加上 `PERM_` 前綴。 | `["product:read", "product:write"]` -> `PERM_product:read`, `PERM_product:write` |
| `scope` | `String`（空白分隔）或 `Array<String>` | 解析後每個元素加上 `SCOPE_` 前綴。 | `"openid profile"` 或 `["openid","profile"]` -> `SCOPE_openid`, `SCOPE_profile` |
| `scp` | `Array<String>` 或 `String`（逗號分隔） | `scope` 的另一種常見形式，每個元素加上 `SCOPE_` 前綴。 | `["read:data", "write:data"]` -> `SCOPE_read:data`, `SCOPE_write:data` |
| `sid` | `String` | Session ID。用於關聯 Refresh Token，實現多設備登入與登出管理。 | `"d8a4f0c5-9b2f-4a3d-9f8a-2c1e0b5d4f3c"` |

**注意**：
- 所有從 claims 提取的權限/角色字串，在轉換為 `GrantedAuthority` 後會進行**合併、去重、排序**，確保輸出穩定。
- 當 claim 值型態不是 `String` 或 `Collection`（例如 `Object`/`Map`）時，會**忽略該 claim**；若 `debugLog=true` 會輸出警告，但不會中斷驗證流程。
- 預設前綴：`ROLE_` / `PERM_` / `SCOPE_`，可透過 `jacky917.security.jwt.prefix.*` 覆寫。

---

## JWT Payload 範例

### 範例 1：具有多重角色的管理員

```json
{
  "iss": "https://auth.jacky917.com",
  "sub": "11223344-5566-7788-99aa-bbccddeeff00",
  "aud": ["api.jacky917.com", "internal-service"],
  "exp": 1735689600,
  "iat": 1735686000,
  "jti": "jwt-id-1",
  "sid": "session-id-user1-device1",
  "roles": ["ADMIN", "CONTENT_MANAGER"],
  "permissions": ["user:read", "user:write", "content:publish"]
}
```
**解析後的 Authorities**: `PERM_content:publish`, `PERM_user:read`, `PERM_user:write`, `ROLE_ADMIN`, `ROLE_CONTENT_MANAGER`

### 範例 2：具備 `scope` 的一般使用者

```json
{
  "iss": "https://auth.jacky917.com",
  "sub": "22334455-6677-8899-aabb-ccddeeff0011",
  "aud": ["api.jacky917.com"],
  "exp": 1735689700,
  "iat": 1735686100,
  "jti": "jwt-id-2",
  "sid": "session-id-user2-device1",
  "roles": ["USER"],
  "scope": "profile.read personal_data.update"
}
```
**解析後的 Authorities**: `ROLE_USER`, `SCOPE_personal_data.update`, `SCOPE_profile.read`

### 範例 3：使用 `scp` 陣列的服務帳號 (Client Credentials)

```json
{
  "iss": "https://auth.jacky917.com",
  "sub": "service-account-batch-processor",
  "aud": ["internal-service"],
  "exp": 1735689800,
  "iat": 1735686200,
  "jti": "jwt-id-3",
  "scp": ["report:generate", "data:aggregate"]
}
```
**解析後的 Authorities**: `SCOPE_data:aggregate`, `SCOPE_report:generate`
