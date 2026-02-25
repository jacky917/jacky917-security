# Starter 設計理念與架構

本文件闡述 `jacky917-security-starter` 的核心設計理念、自動配置策略、擴展點與預設安全行為。

## 核心原則
1.  **約定優於配置 (Convention over Configuration)**：提供合理的預設行為，開發者只需在必要時進行配置。
2.  **最小化依賴**：僅引入必要的 Spring Security 和 JWT 解析庫，避免不必要的複雜性。
3.  **可觀測性 (Observability)**：提供清晰的日誌與 Actuator 端點，方便排查問題。
4.  **安全預設 (Secure by Default)**：預設行為應為最安全的選項，例如預設拒絕所有未明確授權的請求。

## 模組責任劃分

- **`jacky917-security-starter`**:
  - `config`: 包含所有 `@Configuration` 和 `@AutoConfiguration` 類。
  - `authentication`: JWT 解析、驗證、轉換為 `Authentication` 物件。
  - `authorization`: `GrantedAuthority` 映射、方法級安全擴展。
  - `properties`: 所有可透過 `application.yml` 配置的屬性類 (`@ConfigurationProperties`)。
  - `exception`: 自訂安全性例外。

- **`demo-resource-server`**:
  - 展示如何引入 Starter。
  - 提供受 `@PreAuthorize` 保護的 REST Controller 範例。
  - 提供 `application.yml` 配置範例。

## 自動配置策略 (`Auto-Configuration`)

Starter 的核心是利用 Spring Boot 的自動配置機制。

1.  **啟用條件**：
    - `@ConditionalOnWebApplication`: 只在 Web 環境中啟用。
    - `@ConditionalOnClass(JwtDecoder.class)`: 當 `spring-security-oauth2-jose.jar` 在 classpath 中時啟用。
    - `@ConditionalOnProperty(name = "jacky917.security.enabled", havingValue = "true", matchIfMissing = true)`: 預設啟用，但可透過設定檔禁用。

2.  **核心配置類 (`JwtSecurityAutoConfiguration`)**:
    - 引入 `SecurityFilterChain` Bean，設定 HTTP 安全規則（如 `csrf().disable()`, `sessionManagement().sessionCreationPolicy(STATELESS)`)。
    - 配置 `JwtAuthenticationConverter` 將 JWT claims 轉換為 `Authentication` 物件。
    - 配置 `JwtDecoder`，根據 `application.yml` 的 `jwk-set-uri` 來解析 JWT。

## 可覆寫與擴展點

為了保持靈活性，幾乎所有核心元件都允許開發者覆寫。

| 元件                       | 預設 Bean (`@Bean`)                                 | 覆寫方式                                 | 用途                                                       |
| -------------------------- | --------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- |
| **JWT 到權限的轉換器**     | `jwtGrantedAuthoritiesConverter`                    | 提供自訂的 `Converter<Jwt, Collection<GrantedAuthority>>` Bean | 從 JWT claims 中提取權限資訊                               |
| **完整的 JWT 驗證轉換器**  | `jwtAuthenticationConverter`                        | 提供自訂的 `JwtAuthenticationConverter` Bean | 客製化 Principal 名稱、權限提取等                           |
| **HTTP 安全過濾鏈**        | `defaultSecurityFilterChain`                        | 提供自訂的 `SecurityFilterChain` Bean，並加上 `@Order` | 完全控制 HTTP 安全規則，如 CORS、公用端點、標頭等      |
| **方法級安全**             | `@EnableMethodSecurity`                             | 繼承 `GlobalMethodSecurityConfiguration` 或提供自訂 `MethodSecurityExpressionHandler` | 新增自訂的表達式（如 `#hasPermission`) 或整合 ABAC 邏輯 |

## Authority 命名規範與覆寫點

Starter 會將 JWT claims 合併為單一 `GrantedAuthority` 集合，並進行去重與排序，預設命名規範如下：

- `roles` -> `ROLE_` 前綴（例如 `ADMIN` -> `ROLE_ADMIN`）
- `permissions` -> `PERM_` 前綴（例如 `product:read` -> `PERM_product:read`）
- `scope` / `scp` -> `SCOPE_` 前綴（例如 `openid` -> `SCOPE_openid`）

可透過 `application.yml` 覆寫 claim 名稱與前綴：

```yaml
jacky917:
  security:
    jwt:
      claims:
        roles: roles
        permissions: permissions
        scope: scope
        scp: scp
      prefix:
        role: ROLE_
        permission: PERM_
        scope: SCOPE_
```

支援的 claim 輸入型態：
- `roles` / `permissions`：`List<String>` 或逗號分隔字串
- `scope` / `scp`：空白分隔字串或 `List<String>`

當 claim 型態不符合預期（非字串、非陣列）時，會忽略該 claim；若 `jacky917.security.debug-log=true`，只輸出 authorities 與警告訊息，不輸出 JWT 原文。

## 預設安全行為

- **CSRF**: 預設禁用 (`disabled`)，因為 API Server 通常是無狀態的。
- **Session**: 預設為無狀態 (`STATELESS`)，不建立 HTTP Session。
- **CORS**: 預設不配置。建議由應用程式或網關層提供一個 `CorsConfigurationSource` Bean 來啟用。
- **匿名存取**: 預設禁用 (`anonymous().disable()`)。所有請求都必須提供有效的 `Authorization` 標頭。
- **錯誤處理**:
  - **401 Unauthorized**: 當 Token 無效、過期或未提供時返回。
  - **403 Forbidden**: 當 Token 有效但權限不足時返回。
- **公鑰來源**: 預設會從 `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` 屬性讀取 JWKS 端點。
