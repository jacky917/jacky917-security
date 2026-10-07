# 疑難排解

依「症狀」查找原因與解法。若問題與某項設計限制有關，會連到 [限制與注意事項](limitations.md)。

---

## 開啟診斷資訊

排查前先打開 Starter 與 Spring Security 的日誌：

```yaml
jacky917:
  security:
    debug-log: true

logging:
  level:
    jacky917.security: DEBUG
    org.springframework.security: DEBUG     # 會顯示每個 filter 的決策，資訊量很大
```

`jacky917.security: DEBUG` 會印出每個請求解析出的 authorities：

```
Extracted authorities: [PERM_order:read, ROLE_USER, SCOPE_profile]
```

> 排查完畢後請關閉，見 [設定參考 — debug-log](configuration.md#debug-log-的作用)。

---

## 啟動失敗

### `No qualifying bean of type 'org.springframework.security.oauth2.jwt.JwtDecoder' available`

**原因**：沒有提供 `JwtDecoder`。Starter 不會自動建立。

**解法**：設定 `spring.security.oauth2.resourceserver.jwt.issuer-uri`（或 `jwk-set-uri`、`public-key-location`），或自訂 `JwtDecoder` Bean。見 [使用指南 §2](getting-started.md#2-提供-jwtdecoder必要)。

### 啟動成功，但所有 API 都沒有被保護 / 註解沒有作用

依序確認：

1. 是否有引入 `spring-boot-starter-web`？Starter 只在 Servlet 應用啟用。
2. `jacky917.security.enabled` 是否被設為 `false`？
3. 啟動日誌中是否有 `Jacky917SecurityAutoConfiguration`？可用 `--debug` 啟動並查看 Condition Evaluation Report：

   ```bash
   java -jar app.jar --debug 2>&1 | grep -A3 Jacky917SecurityAutoConfiguration
   ```

4. 註解沒作用時，確認 `jacky917.security.method-security.enabled` 不是 `false`，且方法是從 Bean 外部呼叫的 `public` 方法（見 [限制 §10](limitations.md#10-方法級授權只對-spring-bean-的外部呼叫生效)）。

---

## 401 Unauthorized

先看回應的 `WWW-Authenticate` 標頭：

```bash
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/me
```

| `WWW-Authenticate` | 意義 | 排查方向 |
|---|---|---|
| `Bearer` | 請求沒有帶 Token | 確認標頭格式是 `Authorization: Bearer <token>`（`Bearer` 後有一個空白） |
| `Bearer error="invalid_token", error_description="Jwt expired at ..."` | Token 已過期 | 重新取得 Token；檢查伺服器時鐘是否同步 |
| `... error_description="... iss claim is not valid"` | issuer 不符 | `issuer-uri` 必須與 Token 的 `iss` **完全一致**（包含結尾斜線） |
| `... error_description="... aud claim is not valid"` 或類似 | audience 不符 | 確認 `audiences` 設定與 Token 的 `aud` |
| `... error_description="... Signed JWT rejected ..."` | 簽章驗證失敗 | 金鑰不一致、演算法不符（`jws-algorithms`），或 JWKS 中找不到 Token header 的 `kid` |
| `... error_description="... Malformed token"` | 不是合法的 JWT | 確認傳的是 Access Token 本身（不是 Refresh Token），且沒有多帶引號、空白或換行 |

### 公開路徑也回 401

- 請求帶了**無效或過期**的 Token。放行路徑仍會驗證帶上來的 Token，見 [限制 §8](limitations.md#8-放行路徑的行為)。
- 自訂了 `permit-all-patterns`，但沒有把該路徑列進去（自訂會取代預設清單）。
- 該路徑的方法上有 `@Require*` 等授權註解。
- 有自訂 `SecurityFilterChain`，`permit-all-patterns` 已不再生效。

### 瀏覽器的 OPTIONS（preflight）請求回 401

Starter 不設定 CORS，見 [使用指南 §9](getting-started.md#9-cors)。

---

## 403 Forbidden

Token 有效，但沒有通過方法級授權。

1. 打開 `jacky917.security: DEBUG`，查看 `Extracted authorities`。
2. 比對註解期待的 authority：

| 症狀 | 可能原因 |
|---|---|
| authorities 是空的 | claim 名稱不符（例如 IdP 用 `authorities` 而不是 `roles`），或 claim 在巢狀結構中（例如 `realm_access.roles`）。見 [設定參考](configuration.md#jwt-claim-與前綴) |
| authorities 有值，但前綴不同（例如 `ROLE_ROLE_ADMIN`） | Token 中的值已經帶了前綴，Starter 又加一次。把 `jwt.prefix.role` 設為空字串，或請 IdP 移除前綴 |
| 修改過 `jwt.prefix.*`，`@RequireRole` 等永遠 403 | 註解前綴固定，見 [限制 §3](limitations.md#3-單一條件註解的前綴固定) |
| `@RequireAny` / `@RequireAll` 永遠 403 | 參數忘了寫前綴，例如寫成 `"ADMIN\|order:read"`，應為 `"ROLE_ADMIN\|PERM_order:read"` |
| 字串型 claim 解析結果不對 | `roles` / `permissions` / `scp` 以逗號分隔，`scope` 以空白分隔 |
| ABAC 規則一直拒絕 | 確認 `authentication.getName()` 是 `sub`，且與資料庫中的 owner 欄位使用相同的識別碼 |

### 403 但回應不是 Starter 的 JSON 格式

業務專案的 `@RestControllerAdvice` 攔截了 `AccessDeniedException`。見 [限制 §12](limitations.md#12-錯誤回應的限制)。

---

## 500 Internal Server Error

### `AnnotationConfigurationException: Please ensure there is one unique annotation of type @PreAuthorize`

同一個方法上有兩個以上的授權註解。見 [限制 §1](limitations.md#1-同一個方法只能有一個授權註解)。

### `SpelParseException` 或 `SpelEvaluationException`

- `@RequireAny` / `@RequireAll` 的參數包含單引號 `'`。
- `@PreAuthorize` 中引用的 Bean 名稱錯誤（`@beanName` 找不到），或 `#參數名` 無法解析（編譯時未加 `-parameters`）。

---

## 權限比預期寬鬆

- 類別與方法都有授權註解時，只會檢查方法上的。見 [限制 §2](limitations.md#2-類別與方法的註解不會合併)。
- `jacky917.security.method-security.enabled=false` 時，註解靜默失效。
- 其他服務的 Token 也能存取：沒有驗證 `aud`。見 [限制 §7](limitations.md#7-starter-本身不驗證-aud)。
- 已登出或已停權的使用者仍能存取：JWT 無法撤銷。見 [限制 §6](limitations.md#6-token-無法撤銷)。

---

## 設定沒有作用

| 設定 | 原因 |
|---|---|
| `spring.security.oauth2.resourceserver.jwt.principal-claim-name` 等 converter 屬性 | 被 Starter 的 converter 取代，見 [限制 §5](limitations.md#5-spring-boot-原生的-jwt-converter-屬性無效) |
| `jacky917.security.permit-all-patterns` | 有自訂的 `SecurityFilterChain` |
| `spring.jackson.*` 對錯誤回應沒效果 | 錯誤回應使用 Starter 內部的 `ObjectMapper` |

---

## 依賴解析失敗

### `401 Unauthorized` 下載 GitHub Packages

- `~/.m2/settings.xml` 的 `<server><id>` 必須與 `pom.xml` 的 `<repository><id>`（`github`）完全一致。
- PAT 需要 `read:packages` 權限，且未過期。

### Could not find artifact ... jacky917-security-parent

業務專案能找到 `jacky917-security-starter`，卻找不到它的 parent POM。代表該版本發佈時沒有一併發佈 parent（例如 `mvn deploy` 的 `-pl` 漏掉了 `.`）。請聯繫維護者以新版本號重新發佈。見 [限制 §16](limitations.md#16-發佈與依賴)。

### Could not find artifact org.springframework.boot:spring-boot-starter-parent:pom:3.5.10-SNAPSHOT

只有 `1.0.0` 會發生：它的 parent POM 依賴 Spring Boot 的 SNAPSHOT 版本。請升級到 `1.1.0` 以上。見 [限制 §16](limitations.md#16-發佈與依賴)。

---

## 本 repo 的建置問題

### 編譯錯誤：`cannot find symbol ... log` / `getXxx()`

Lombok 沒有執行。JDK 23 起不再自動探索 annotation processor，本專案已在根 `pom.xml` 以 `annotationProcessorPaths` 明確宣告。若仍發生，確認沒有使用舊版的 `pom.xml`，或 IDE 已啟用 annotation processing。

### Demo 啟動時連不到 MySQL

`demo-resource-server` 預設連線 `localhost:3307/demo_db`（帳密 `root` / `root`）。可用 Docker 啟動：

```bash
docker run -d --name jacky917-demo-mysql -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=demo_db mysql:8.4
```

執行 `mvn verify` 時不需要 MySQL，測試會使用 H2。
