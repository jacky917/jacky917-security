# jacky917-security-starter

專為 **Resource Server（API 服務）** 設計的 Spring Boot Starter。引入一個依賴、提供一個 `JwtDecoder`，即可得到：

- 無狀態的 JWT Bearer Token 驗證（所有請求預設需驗證，可設定放行路徑）
- JWT claims（`roles` / `permissions` / `scope` / `scp`）自動轉換為 Spring Security authority
- 開箱即用的方法級授權註解：`@RequireRole`、`@RequirePerm`、`@RequireScope`、`@RequireAny`、`@RequireAll`
- 統一的 401 / 403 JSON 錯誤回應

```java
@RestController
class OrderController {

    @RequirePerm("order:read")                       // 需要 PERM_order:read
    @GetMapping("/orders")
    List<Order> list() { ... }

    @RequireAll("ROLE_ADMIN|PERM_order:write")       // 同時需要兩者
    @DeleteMapping("/orders/{id}")
    void delete(@PathVariable String id) { ... }
}
```

> [!IMPORTANT]
> 本 Starter **不負責簽發 Token**，也**不會自動建立 `JwtDecoder`**。你必須透過 `spring.security.oauth2.resourceserver.jwt.*` 設定或自訂 Bean 提供 `JwtDecoder`，否則應用程式無法啟動。詳見 [使用指南](docs/getting-started.md#2-提供-jwtdecoder必要)。

---

## 文件導覽

| 文件 | 內容 |
|---|---|
| [使用指南](docs/getting-started.md) | 從引入依賴到上線的完整步驟：JwtDecoder、放行路徑、註解、ABAC、錯誤回應、覆寫元件、測試寫法 |
| [設定參考](docs/configuration.md) | 所有 `jacky917.security.*` 屬性、預設值，以及與 Spring Boot 原生屬性的關係 |
| [限制與注意事項](docs/limitations.md) | **上線前必讀**：已知限制、容易踩到的行為與對應的解法 |
| [疑難排解](docs/troubleshooting.md) | 常見錯誤訊息與排查步驟 |
| [JWT Claims 契約](docs/jwt-claims.md) | Token 內容格式、claim 解析規則與範例 |
| [授權模型](docs/authorization-model.md) | RBAC / Permission / Scope / ABAC 的使用方式與組合 |
| [Starter 設計](docs/starter-design.md) | 自動配置架構、Bean 清單、啟用條件與擴充點 |
| [E2E 測試指南](docs/e2e-testing.md) | 同時啟動兩個 Demo 服務，走完取 Token → 呼叫 API 的流程 |
| [GitHub Packages](docs/github-packages.md) | 發佈與引用設定 |
| [2.0 總設計](docs/v2-overview.md) | **規劃中**：升級 Spring Boot 4.1 與新增 Authorization Server 的目標、里程碑、破壞性變更與待確認事項 |
| [Spring Boot 4.1 升級設計](docs/boot4-migration-design.md)、[Repo 拆分設計](docs/repo-structure-design.md) | 2.0 的升級影響清單與步驟；repo 結構、命名、建置、版本與 CI |
| [AS 資料模型](docs/auth-server-data-model.md)、[AS 詳細設計](docs/auth-server-detailed-design.md) | **規劃中**：Authorization Server 的完整表設計（DDL、索引、狀態機、Flyway），以及元件、流程、Token、威脅模型與測試案例 |
| [Authorization Server 設計](docs/auth-server-design.md) | **規劃中**：以 Spring Authorization Server 建置登入服務（支援第三方登入）的架構、決策、資料表與實作計畫 |
| [Refresh Token Rotation](docs/refresh-rotation.md)、[資料表設計](docs/database-schema.md) | Authorization Server 端的早期參考設計 |

---

## 相容性

| 項目 | 版本 / 條件 |
|---|---|
| Java | 21 以上（`2.x` 已在 JDK 23 建置驗證） |
| Spring Boot | **4.1.x**（`2.x`，本分支以 4.1.1 建置） |
| Spring Security | 7.1.x（由 Spring Boot 管理） |
| 應用程式類型 | **僅支援 Servlet（Spring MVC）**，不支援 WebFlux |
| Token 格式 | JWT（JWS）。不支援 Opaque Token / Token Introspection |

### 版本線

| Starter 版本 | Spring Boot | 狀態 |
|---|---|---|
| `1.x`（`1.x` 分支） | 3.5.x | 只提供安全修補；Spring Boot 3.5 的開源支援已於 2026-06-30 結束 |
| `2.x`（`main`） | 4.1.x | 開發中，尚未發佈正式版 |

---

## 模組

| 模組 | 說明 | 是否發佈 |
|---|---|---|
| `jacky917-security-starter` | 聚合依賴，**業務專案只需引入這一個** | ✅ |
| `jacky917-security-autoconfigure` | 自動配置：`SecurityFilterChain`、claims → authorities、401/403 JSON、方法級授權 | ✅ |
| `jacky917-security-annotations` | `@RequireRole` / `@RequirePerm` / `@RequireScope` / `@RequireAny` / `@RequireAll` | ✅ |
| `demo-resource-server` | 示範如何使用 Starter（RBAC、AND/OR、資料庫導向 ABAC、Swagger） | ❌ |
| `demo-authorization-server` | 最小化的測試用 Token 簽發服務 | ❌ |

---

## 快速開始（業務專案）

### 1. 設定 GitHub Packages 存取

GitHub Packages **即使是公開套件也需要認證**。在 `~/.m2/settings.xml` 加入具有 `read:packages` 權限的 PAT：

```xml
<servers>
    <server>
        <id>github</id>
        <username>YOUR_GITHUB_USERNAME</username>
        <password>YOUR_GITHUB_PAT_WITH_READ_PACKAGES</password>
    </server>
</servers>
```

在業務專案的 `pom.xml` 加入 repository（`id` 必須與上面的 `server.id` 一致）：

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/jacky917/jacky917-security-starter</url>
    </repository>
</repositories>
```

### 2. 引入依賴

```xml
<dependency>
    <groupId>com.github.jacky917</groupId>
    <artifactId>jacky917-security-starter</artifactId>
    <version>2.0.0-SNAPSHOT</version>   <!-- Spring Boot 3.5 請用 1.1.0 -->
</dependency>
<!-- Starter 只支援 Servlet 應用，請確認已引入 Spring MVC -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webmvc</artifactId>   <!-- Spring Boot 3.5 為 spring-boot-starter-web -->
</dependency>
```

### 3. 提供 JwtDecoder（以 Authorization Server 的 issuer 為例）

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com      # 自動探索 JWKS，並驗證 iss
          audiences: my-api                          # 建議設定，驗證 aud

jacky917:
  security:
    permit-all-patterns:                             # 注意：設定後會「取代」預設值
      - /public/**
      - /actuator/health
      - /v3/api-docs/**
      - /swagger-ui/**
      - /swagger-ui.html
```

### 4. 在 Controller 使用註解

```java
@RequireRole("ADMIN")              // ROLE_ADMIN
@RequirePerm("order:read")         // PERM_order:read
@RequireScope("profile.read")      // SCOPE_profile.read
@RequireAny("ROLE_ADMIN|PERM_order:read")
@RequireAll("ROLE_ADMIN|PERM_order:write")
```

> [!WARNING]
> **同一個方法只能放一個授權註解。** 上述五個註解底層都是 `@PreAuthorize`，與 `@PreAuthorize` 或彼此疊加時，會在**呼叫時**拋出 `AnnotationConfigurationException`（HTTP 500），編譯與啟動都不會報錯。需要組合條件時請改寫成單一 `@PreAuthorize`。詳見 [限制與注意事項](docs/limitations.md#1-同一個方法只能有一個授權註解)。

完整說明請看 [使用指南](docs/getting-started.md)。

---

## 預設行為一覽

| 項目 | 預設 |
|---|---|
| 驗證方式 | `Authorization: Bearer <JWT>` |
| 未列入 `permit-all-patterns` 的請求 | 全部需要驗證 |
| Session | `STATELESS`（不建立 HttpSession） |
| CSRF | 停用 |
| CORS | 未設定（需自行提供，見 [使用指南](docs/getting-started.md#9-cors)） |
| Principal 名稱（`authentication.getName()`） | JWT 的 `sub` |
| claims → authority | `roles` → `ROLE_*`、`permissions` → `PERM_*`、`scope` / `scp` → `SCOPE_*` |
| 方法級授權 | 啟用（`@PreAuthorize`、`@PostAuthorize`、`@Secured`、自訂註解） |
| 401 / 403 | JSON 回應；401 另帶 RFC 6750 `WWW-Authenticate` 標頭（含 RFC 9728 的 `resource_metadata`） |
| `Authentication` 中的額外 authority | Spring Security 7 會自動加入 `FACTOR_BEARER`，代表以 Bearer Token 驗證 |

401 回應範例：

```json
{
  "timestamp": "2026-10-07T01:23:45.678Z",
  "status": 401,
  "errorCode": "Unauthorized",
  "message": "未經驗證，無法存取資源",
  "path": "/orders"
}
```

---

## 本地開發（本 repo）

### 環境需求

- JDK 21 以上
- Maven 3.8 以上
- Docker（或本機 MySQL 8.4），僅執行 `demo-resource-server` 時需要；跑測試不需要（測試使用 H2）

### 建置與測試

```bash
mvn clean verify
```

### 執行 Demo

1) 啟動 MySQL（`demo-resource-server` 預設連線 `localhost:3307/demo_db`，帳密 `root` / `root`）

```bash
docker run -d --name jacky917-demo-mysql -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=demo_db mysql:8.4
```

2) 安裝本地模組

```bash
mvn -DskipTests install
```

3) 啟動 Resource Server（port 8080）

```bash
mvn -pl demo-resource-server spring-boot:run
```

4) 另開終端啟動 Authorization Server（port 8081）

```bash
mvn -pl demo-authorization-server spring-boot:run
```

5) 取得 Token 並呼叫 API

```bash
TOKEN=$(curl -s -X POST http://localhost:8081/oauth2/token -H "Content-Type: application/json" -d '{"username":"alice","password":"password"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')
```

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secure/me
```

不想啟動 Auth Server 時，也可以用 CLI 直接產生測試 JWT：

```bash
mvn -pl demo-resource-server -q exec:java -Dexec.mainClass=jacky917.demo.resourceserver.tools.GenerateTestJwtMain -Dexec.args="--sub=alice --roles=A --perms=bb,clip:read --scope=profile.read --minutes=30"
```

完整流程與預期結果見 [E2E 測試指南](docs/e2e-testing.md)。

### Demo 端點

| 端點 | 規則 | 寫法 |
|---|---|---|
| `GET /public/ping` | 匿名可存取 | `permit-all-patterns` |
| `GET /secure/me` | 需驗證 | 無註解 |
| `GET /secure/role-a` | 需 `ROLE_A` | `@RequireRole("A")` |
| `GET /secure/perm-bb` | 需 `PERM_bb` | `@RequirePerm("bb")` |
| `GET /secure/and` | 需 `ROLE_A` **且** `PERM_bb` | `@RequireAll("ROLE_A\|PERM_bb")` |
| `GET /secure/or` | 需 `ROLE_A` **或** `PERM_bb` | `@RequireAny("ROLE_A\|PERM_bb")` |
| `GET /secure/abac/{clipId}` | 需 `PERM_clip:read`，且 `clip.ownerId == JWT sub` | `@PreAuthorize` + `@authzService` |

Demo 內建資料：`demo-001`（owner：`alice`）、`private-001`（owner：`bob`）。

### Swagger UI

- Resource Server：<http://localhost:8080/swagger-ui.html>
- Authorization Server：<http://localhost:8081/swagger-ui.html>

---

## FAQ

**Q：這個 Starter 和 Spring Boot 原生的 `spring-boot-starter-security-oauth2-resource-server` 有什麼差別？**

本 Starter 建立在原生 Resource Server 之上（JWT 驗證本身仍由 Spring Security 完成），額外提供：多 claim 來源的 authority 映射、`@Require*` 註解、`@RequireAny` / `@RequireAll` 的 AND/OR 語法、統一的 JSON 錯誤格式，以及預設全部需驗證的 filter chain。它不取代 JWT 驗證邏輯，也不支援 Opaque Token。

**Q：我已經有自己的 `SecurityFilterChain`，還能用嗎？**

可以，但 Starter 的 filter chain 會整個讓位，放行路徑、JSON 錯誤回應都要自己設定。`JwtAuthenticationConverter` 與註解仍可沿用。見 [使用指南 §8](docs/getting-started.md#8-覆寫預設元件)。

**Q：為什麼設定了 `spring.security.oauth2.resourceserver.jwt.principal-claim-name` 沒有效果？**

Starter 會提供自己的 `JwtAuthenticationConverter`，使 Spring Boot 依該屬性建立的 converter 不會生效。見 [限制與注意事項](docs/limitations.md#5-spring-boot-原生的-jwt-converter-屬性無效)。

**Q：如何實作「只有資源擁有者能存取」這類規則？**

用 `@PreAuthorize` 呼叫自訂 Bean，例如 `@PreAuthorize("hasAuthority('PERM_clip:read') and @authzService.canAccessClip(authentication, #clipId)")`。見 [授權模型 — ABAC](docs/authorization-model.md#abac資源屬性授權)。
