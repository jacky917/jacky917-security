# jacky917-security-starter

一個為「Resource Server（資源伺服器）」設計的 Spring Boot Starter，旨在提供一個安全、可擴展、易於維護的 JWT 權限驗證與授權框架。

本專案遵循嚴格的開發規範，所有變更都必須有對應的文件更新、進度追蹤與自動化測試，以確保高品質交付。

## 核心目標
- **標準化 JWT 驗證**：提供一個開箱即用的 JWT `AuthenticationProvider`，自動處理 Token 解析、簽章驗證與 claims 提取。
- **靈活的權限映射**：支援從 JWT claims（如 `roles`, `permissions`, `scope`, `scp`）到 Spring Security `GrantedAuthority` 的自動轉換。
- **方法級授權**：整合 Spring Security 的 `@PreAuthorize`，並提供自訂授權註解的擴展點。
- **可配置與可覆寫**：所有核心元件都應為可選（Conditional）或可替換（Primary/Bean），允許開發者根據需求自訂。
- **高品質文件與範例**：提供完整的文件、清晰的範例（demo app）與可執行的測試案例。

## 模組清單

- `jacky917-security-annotations`：提供 `@RequireRole`、`@RequirePerm`、`@RequireAny`、`@RequireAll`、`@RequireScope`。
- `jacky917-security-autoconfigure`：提供 `SecurityFilterChain`、JWT 權限映射、統一 401/403 JSON 錯誤回應。
- `jacky917-security-starter`：聚合依賴入口，供外部專案直接引用。
- `demo-resource-server`：完整示範 API（permitAll、authenticated、RBAC、AND/OR、ABAC）。
- `demo-authorization-server`：最小化 Mock JWT 簽發中心，供 E2E 測試使用。

## 快速開始

### 環境要求
- Java 21
- Maven 3.8+
- MySQL 8.4（`demo-resource-server` 執行時需要）

### 建置專案
```bash
# 第一次或依賴更新時
mvn -U clean install

# 一般建置與測試
mvn clean verify
```

### Maven 導入範例（發布版）

```xml
<dependency>
    <groupId>com.github.jacky917</groupId>
    <artifactId>jacky917-security-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 如何執行測試
本專案包含高品質的單元測試與整合測試。
```bash
# 執行所有測試
mvn clean verify
```

### 如何執行 Demo App

1) 先安裝本地模組（避免 `spring-boot:run` 抓不到本地 SNAPSHOT）
```bash
mvn -U -DskipTests install
```

2) 啟動 `demo-resource-server`
```bash
mvn -pl demo-resource-server -U spring-boot:run
```

3) 啟動 `demo-authorization-server`
```bash
mvn -pl demo-authorization-server -U spring-boot:run
```

### MySQL 8.4 準備（供 demo-resource-server 使用）

`demo-resource-server` 預設連線設定：

- `jdbc:mysql://localhost:3306/demo_db`
- username: `demo_user`
- password: `demo_pass`
- `spring.jpa.hibernate.ddl-auto=update`

請先建立資料庫與帳號（或調整 `demo-resource-server/src/main/resources/application.yml`）。

### 本地產生測試 JWT（JWK + CLI）

`demo-resource-server` 內含 `HS256` 測試 JWK：`demo-resource-server/src/main/resources/demo/jwk/demo-hs256.jwk.json`，
並提供 CLI：`jacky917.demo.resourceserver.tools.GenerateTestJwtMain`。

```bash
mvn -pl demo-resource-server -q exec:java \
  -Dexec.mainClass=jacky917.demo.resourceserver.tools.GenerateTestJwtMain \
  -Dexec.args="--sub=alice --roles=A --perms=bb,clip:read --scope=profile.read --minutes=30"
```

CLI 會輸出 JWT 與 `export TOKEN="..."`，可直接貼到 shell。

### Demo 端點清單

- `GET /public/ping`：`permitAll`
- `GET /secure/me`：需已驗證
- `GET /secure/role-a`：需 `ROLE_A`
- `GET /secure/perm-bb`：需 `PERM_bb`
- `GET /secure/and`：需同時具備 `ROLE_A` + `PERM_bb`
- `GET /secure/or`：具備 `ROLE_A` 或 `PERM_bb` 任一即可
- `GET /secure/abac/{clipId}`：需 `PERM_clip:read` 且資料庫 `clip.ownerId == JWT sub`

### Swagger UI

- Resource Server: `http://localhost:8080/swagger-ui.html`
- Auth Server: `http://localhost:8081/swagger-ui.html`

Starter 預設已放行 Swagger/OpenAPI 路徑（`/swagger-ui/**`, `/v3/api-docs/**`）。

### curl 驗證範例

```bash
# 1) 匿名端點
curl http://localhost:8080/public/ping

# 2) 受保護端點（401）
curl http://localhost:8080/secure/me

# 3) 帶 JWT（200）
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/me

# 4) AND/OR/ABAC 示例
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/and
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/or
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/abac/demo-001
```

### 端到端（E2E）執行範例

完整流程（同時啟動 auth-server + resource-server，先拿 token 再打受保護端點）請參考：

- `docs/e2e-testing.md`

## FAQ

**Q1: 這個 Starter 跟 Spring Security OAuth2 Resource Server 有什麼不同？**

**A1:** 本專案旨在提供一個更輕量、更專注於「JWT claims 到 authorities 映射」的客製化解決方案。它簡化了配置，並針對特定授權模型（如多種 claims 來源、自訂 ABAC 邏輯）提供了更直觀的擴展點，同時也移除了對 OAuth2 完整流程（如 `token_introspection` 端點）的依賴。

**Q2: Demo 的 JWT 驗證金鑰從哪裡來？**

**A2:** `demo-resource-server` 目前使用 resources 內建的對稱式 JWK（`demo-hs256.jwk.json`）。`GenerateTestJwtMain` 與 `JwtDecoder` 會共用同一把測試金鑰，方便本地驗證。

**Q3: 如何擴展權限判斷邏輯？**

**A3:** 你可以提供自己的 `AccessDecisionVoter` 或 `AuthorizationManager` Bean，並使用 `@Primary` 來覆寫預設行為。詳細請參考 `docs/starter-design.md`。
