# JWT Claims 契約

本文件定義了此安全框架所期望的 JWT (JSON Web Token) Claims 結構。所有傳入的 JWT 都應遵循此契約，以確保權限系統能正確解析與運作。

## 標準 Claims

> [!IMPORTANT]
> 下表的「強制性」是**建議的 Token 契約**。實際驗證哪些標準 claim，完全取決於業務專案提供的 `JwtDecoder`，Starter 本身不會檢查：
>
> | Claim | Spring Boot 預設是否驗證 |
> |---|---|
> | `exp`、`nbf` | ✅ 一律驗證（允許 60 秒時鐘誤差） |
> | `iss` | 只有設定 `issuer-uri`，或自訂 decoder 使用 `JwtValidators.createDefaultWithIssuer(...)` 時才驗證 |
> | `aud` | 只有設定 `audiences`，或自訂 decoder 加入 audience validator 時才驗證 |
> | `iat`、`jti`、`sid` | ❌ 不驗證 |
>
> 設定方式見 [使用指南 §2](getting-started.md#2-提供-jwtdecoder必要)，風險說明見 [限制 §6、§7](limitations.md#6-token-無法撤銷)。

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
| `sid` | `String` | Session ID。由 Authorization Server 用於關聯 Refresh Token、管理多裝置登入與登出。**Starter 不讀取也不驗證此 claim**，業務程式可透過 `jwt.getClaimAsString("sid")` 取得。規劃中的 Authorization Server（2.x）改以 `asid` 傳遞登入 Session，ID Token 的 `sid` 交由 Spring Security 管理，見 [AS 詳細設計 D20](../design/auth-server-detailed-design.md#d20-session-識別-claim)。 | `"d8a4f0c5-9b2f-4a3d-9f8a-2c1e0b5d4f3c"` |

**注意**：
- 所有從 claims 提取的權限/角色字串，在轉換為 `GrantedAuthority` 後會進行**合併、去重、排序**，確保輸出穩定。
- 每個值會先去除前後空白，空字串與陣列中的 `null` 元素會被略過；陣列中的非字串元素（例如數字）會以 `toString()` 轉換。
- 當 claim 值型態不是 `String` 或 `Collection`（例如物件／`Map`）時，會**忽略該 claim** 並輸出一行 WARN 日誌，不會中斷驗證流程。
- 只讀取**頂層** claim，不支援 `realm_access.roles` 這類巢狀路徑。
- `principal`（`authentication.getName()`）固定取自 `sub`。
- Spring Security 7 會在 `Authentication` 中另外加入 `FACTOR_BEARER`（代表以 Bearer Token 驗證）。下方範例列出的「解析後的 Authorities」只包含由 claims 映射出的部分。
- 預設前綴：`ROLE_` / `PERM_` / `SCOPE_`，可透過 `jacky917.security.jwt.prefix.*` 覆寫；claim 名稱可透過 `jacky917.security.jwt.claims.*` 覆寫。見 [設定參考](configuration.md#jwt-claim-與前綴)。
- 修改前綴後，`@RequireRole` / `@RequirePerm` / `@RequireScope` 會跟著使用新前綴（2.0 起）；`@RequireAny` / `@RequireAll` 使用完整名稱，需自行調整。

### 給 Authorization Server 的建議

- Token 中的值**不要自帶前綴**（寫 `"ADMIN"`，不要寫 `"ROLE_ADMIN"`），否則會變成 `ROLE_ROLE_ADMIN`。
- 優先使用 JSON 陣列，避免值本身含有逗號或空白時被錯誤切割。
- 權限數量很多時，Token 會變大並出現在每個請求的標頭中。若超過數 KB，考慮改以角色傳遞，或在 Resource Server 端依角色查詢權限。

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
