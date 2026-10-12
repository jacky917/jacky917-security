# E2E 測試指南（登入服務 + API + BFF）

本文件示範如何以三個範例走完整的流程：瀏覽器透過 `example-bff` 登入 `example-authorization-server`，再以 Access Token 呼叫 `example-resource-server`。

```mermaid
sequenceDiagram
    autonumber
    participant B as 瀏覽器
    participant F as example-bff（8082）
    participant AS as example-authorization-server（9000）
    participant RS as example-resource-server（8080）

    B->>F: GET /oauth2/authorization/jacky917
    F-->>B: 302 → AS /oauth2/authorize（PKCE）
    B->>AS: 登入頁，送出帳密
    AS-->>B: 302 → BFF /login/oauth2/code/jacky917?code=…
    B->>F: 帶著授權碼
    F->>AS: 以授權碼與 code_verifier 換 Token（伺服器之間）
    B->>F: GET /api/secure/me（只有 Session Cookie）
    F->>RS: GET /secure/me（Authorization: Bearer …）
    RS->>AS: 取得 JWKS（第一次）
    RS-->>F: 200
    F-->>B: 200
```

## 1. 自動化的端對端測試

`e2e-tests` 模組在同一個 JVM 中以隨機埠號啟動登入服務、Resource Server、audience 不同的第二個 Resource Server 與 BFF，再以保存 Cookie 的 HTTP client 模擬瀏覽器：

```bash
mvn -pl e2e-tests -am verify
```

| 測試 | 驗證內容 |
|---|---|
| alice 登入並呼叫 API | 登入頁（含 CSRF）→ 授權碼 → BFF 換 Token → `/api/secure/me` 200、`/api/secure/role-a` 200（詳細設計 T-E2E-01） |
| bob 沒有角色 A | Resource Server 回 403，BFF 原樣轉回 |
| audience 檢查 | 同一個 Token：`aud=jacky917-api` 的服務 200，設定為 `other-api` 的服務 401（T-E2E-03） |
| 登出 | BFF 結束 Session → 登入服務的 `/connect/logout` → 回到 BFF 首頁；之後兩邊都需要重新登入 |
| 第三方應用程式 | 以第三方 client `partner-demo` 登入：同意畫面 → 允許 → token 不含角色，`/api/secure/perm-bb` 200（scope `bb.read` 對應權限 `bb`）、`/api/secure/role-a` 403 |
| 管理 API | 以 `client_credentials` 取得 `as:user:read` 的 token：`/admin/api/users` 200，沒有權限的 `/admin/api/roles` 403 |

CI 每次都會執行，不需要 Docker 或資料庫（登入服務使用暫存的 SQLite，Resource Server 使用 H2）。

e2e 測試以參數提供所有設定，不讀範例的 `application.yml`。範例登入服務自己的測試（`examples/example-authorization-server`）則使用範例的設定檔，走完 demo 的其他流程：

| 測試 | 驗證內容 |
|---|---|
| admin 首次登入 | 強制啟用兩步驟驗證（`mfa.required-roles: AS_ADMIN`）→ 顯示復原碼 → 強制變更密碼 → 回到授權請求 |
| 註冊與 Email 驗證 | 信件寫在日誌中（`account.mail.log-links`），以日誌的連結與註冊時的密碼驗證後登入 |
| 忘記密碼 | 以日誌的重設連結設定新密碼，舊密碼失效 |
| 示範 client | `partner-demo` 要求同意、`bb.read` 對應權限 `bb`；`admin-demo` 可以呼叫管理 API |

## 2. 手動執行

### 前置需求

- JDK 21 以上、Maven 3.8 以上
- Docker（或本機 MySQL 8.4）：`example-resource-server` 執行時需要

### Step 0：啟動 MySQL 並安裝本地模組

```bash
docker run -d --name jacky917-demo-mysql -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=demo_db mysql:8.4
```

```bash
mvn -DskipTests install
```

### Step 1：依序啟動三個服務

```bash
mvn -pl examples/example-authorization-server spring-boot:run
```

```bash
mvn -pl examples/example-resource-server spring-boot:run
```

```bash
mvn -pl examples/example-bff spring-boot:run
```

| 服務 | 網址 | 說明 |
|---|---|---|
| 登入服務 | <http://localhost:9000> | 資料存在 `examples/example-authorization-server/data/`（SQLite，第一次啟動時建立）；首次啟動建立示範使用者 |
| API | <http://localhost:8080> | 以登入服務的 JWKS 驗證 Token，並檢查 `iss` 與 `aud` |
| BFF | <http://localhost:8082> | 網頁與 API 代理 |

範例登入服務的 client：

| client | 用途 |
|---|---|
| `web-bff` | BFF 本身（第一方） |
| `partner-demo` | 第三方應用程式的示範：BFF 首頁的「以第三方應用程式登入」使用它，第一次登入時出現同意畫面 |
| `report-batch` | 服務對服務（`client_credentials`，Step 3） |
| `admin-demo` | 管理 API 的示範（`client_credentials`，只能讀取使用者與稽核紀錄，Step 4） |

各 client 的 secret 可以用環境變數設定（`WEB_BFF_SECRET`、`PARTNER_DEMO_SECRET`、`REPORT_BATCH_SECRET`、`ADMIN_DEMO_SECRET`）；沒有設定時使用 `application.yml` 中 `${…:預設值}` 冒號後面的示範值，**只限本機**。下面的 curl 指令從同名環境變數讀取 secret：沒有自行設定時，請把示範值設定到執行 curl 的終端機。

示範帳號（密碼皆為 `demo-password-123`，可用環境變數 `DEMO_USER_PASSWORD` 修改）：

| 帳號 | 角色 | 權限 |
|---|---|---|
| `alice` | `USER`、`A` | `bb`、`clip:read` |
| `bob` | `USER` | — |
| `admin` | `USER`、`AS_ADMIN` | `as:*`（密碼 `admin-password-123`；第一次登入時先變更密碼，再以驗證器 App 啟用兩步驟驗證） |

### Step 2：瀏覽器

1. 開啟 <http://localhost:8082>，按「登入」，以 `alice` 登入。
2. 按「GET /secure/role-a」：200。改以 `bob` 登入時為 403。
3. 按「登出」：同時登出 BFF 與登入服務，回到首頁。

瀏覽器只會看到 BFF 的 Session Cookie；Access Token 與 Refresh Token 保存在 BFF 的 Session 中。

第三方應用程式（同意畫面）：

1. 按「以第三方應用程式登入」，以 `alice` 登入。第一次會出現同意畫面：應用程式名稱、說明、隱私權政策，以及要求的權限（基本資料、Email、使用權限 bb），可以取消勾選。
2. 按「允許」後回到 BFF 首頁，顯示「透過 第三方應用程式 partner-demo」。
3. 「GET /secure/perm-bb」為 200：scope `bb.read` 對應權限 `bb`，alice 也擁有它。「GET /secure/role-a」為 403：第三方應用程式的 token 不含角色。以 `bob` 試時 perm-bb 也是 403（bob 沒有權限 bb）。
4. 在帳號頁的「已授權的應用程式」按「移除存取權」：第三方應用程式的 Refresh Token 立即失效，下一次登入會再次出現同意畫面。

登入服務本身的頁面（<http://localhost:9000/jacky917/account>）也可以試：

- 帳號頁：登入中的裝置、變更密碼、兩步驟驗證（以 Google Authenticator 等 App 掃描 QR code）。
- 登入頁的「忘記密碼？」與「建立帳號」：範例沒有 SMTP，信件內容（含連結）寫在登入服務的日誌（`Account mail to …`）中，複製到瀏覽器開啟。
- 以 `admin` 登入：先變更密碼，再啟用兩步驟驗證（`mfa.required-roles: AS_ADMIN`）。

### Step 3：服務對服務（client_credentials）

```bash
TOKEN=$(curl -s -u "report-batch:$REPORT_BATCH_SECRET" -d grant_type=client_credentials -d scope=report.generate http://localhost:9000/oauth2/token | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
```

```bash
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/me
```

預期 200；`sub` 為 `report-batch`，Token 中只有 `scope`，沒有角色與權限。

### Step 4：管理 API

`admin-demo` 只有 `as:user:read` 與 `as:audit:read`：

```bash
ADMIN_TOKEN=$(curl -s -u "admin-demo:$ADMIN_DEMO_SECRET" -d grant_type=client_credentials -d "scope=as:user:read as:audit:read" http://localhost:9000/oauth2/token | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
```

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "http://localhost:9000/admin/api/users?query=alice"
```

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "http://localhost:9000/admin/api/audit/logins?size=5"
```

預期回傳 `{"items": [...], "page": 0, "size": …, "total": …}`。沒有權限的端點（例如 `/admin/api/roles`）回 403。管理員以 `admin` 登入的方式取得 token、所有端點與權限見 [使用指南 §9](../authorization-server/getting-started.md#9-管理-api)。

### 選擇性：依 scope 決定 `aud`

在範例登入服務的 `application.yml` 加上 `jacky917.security.authorization-server.token.audience-strategy: per-scope`，並以管理 API 建立 API resource、把 scope 指到它（`POST /admin/api/api-resources`、`PUT /admin/api/scopes/{code}` 的 `apiResource`）。之後要求該 scope 的 token，`aud` 就是那個 API resource；Resource Server 的 `audiences` 設為同一個代碼即可只接受它（見 [使用指南 §7](../authorization-server/getting-started.md#7-token-內容)）。

### Step 5：錯誤情境

```bash
curl -i http://localhost:8080/secure/me
```

預期 401，`WWW-Authenticate: Bearer resource_metadata="…"`。

```bash
curl -i -H "Authorization: Bearer not-a-jwt" http://localhost:8080/secure/me
```

預期 401，`WWW-Authenticate` 帶 `error="invalid_token"`。

## 3. 疑難排解

| 症狀 | 原因 | 解法 |
|---|---|---|
| 登入後又回到登入頁、或出現 `authorization_request_not_found` | 登入服務與 BFF 在同一台主機、都使用 `JSESSIONID`，Cookie 互相覆蓋（瀏覽器的 Cookie 不區分埠號） | 為登入服務設定不同的 Cookie 名稱（範例已設定 `JACKY917_AS_SESSION`） |
| API 回 401，日誌顯示 `The iss claim is not valid` | API 的 `issuer-uri` 與登入服務的 `issuer` 不同（例如 `localhost` 與 `127.0.0.1`） | 兩者必須完全相同 |
| API 回 401，日誌顯示 `aud` 不符 | Token 不是發給這個服務的 | 檢查 `spring.security.oauth2.resourceserver.jwt.audiences` 與登入服務的 `token.audience` |
| `/secure/abac/demo-001` 回 403 | ABAC 比對 Token 的 `sub`（使用者 ID），示範資料的 owner 是字串 `alice` | 把 `clip.owner_id` 改成 alice 的使用者 ID |
| 登入服務啟動失敗：`Cannot decrypt signing key` | `JACKY917_AS_ENCRYPTION_KEY` 與建立資料庫時不同 | 使用原本的主金鑰；或刪除 `data/` 重新建立（所有 Token 失效） |
