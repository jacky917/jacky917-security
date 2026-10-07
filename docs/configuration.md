# 設定參考

本文件列出 `jacky917-security-starter` 的所有設定屬性，以及它們與 Spring Boot 原生 `spring.security.oauth2.resourceserver.*` 屬性的關係。

屬性對應的 Java 類別為 [`Jacky917SecurityProperties`](../jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/properties/Jacky917SecurityProperties.java)。IDE（IntelliJ IDEA、VS Code Spring Boot Tools）會依據 configuration metadata 提供自動完成與說明。

---

## 完整範例（皆為預設值）

```yaml
jacky917:
  security:
    enabled: true
    debug-log: false
    permit-all-patterns:
      - /actuator/health
      - /v3/api-docs
      - /v3/api-docs/**
      - /swagger-ui/**
      - /swagger-ui.html
      - /swagger-ui/index.html
    method-security:
      enabled: true
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

---

## 一般設定

| 屬性 | 型別 | 預設值 | 說明 |
|---|---|---|---|
| `jacky917.security.enabled` | `boolean` | `true` | 是否啟用整個自動配置。設為 `false` 時，Starter 不建立任何 Bean。 |
| `jacky917.security.debug-log` | `boolean` | `false` | 是否輸出額外的診斷日誌，詳見下方說明。 |
| `jacky917.security.permit-all-patterns` | `List<String>` | 見上方範例 | 不需驗證即可存取的路徑樣式。**設定後會取代預設清單，而不是附加。** |
| `jacky917.security.method-security.enabled` | `boolean` | `true` | 是否啟用方法級授權（`@PreAuthorize`、`@PostAuthorize`、`@Secured`、`@Require*`）。 |

### `debug-log` 的作用

開啟後會輸出：

| 時機 | 等級 | 內容 |
|---|---|---|
| 建立 filter chain 時 | INFO | `Initializing Jacky917SecurityFilterChain...` |
| 每次成功解析 Token | DEBUG | `Extracted authorities: [...]` |
| 每次回傳 401 / 403 | WARN | 狀態碼、訊息、路徑、例外類別名稱 |

注意事項：

- DEBUG 訊息還需要把 logger 等級調成 DEBUG 才看得到：

  ```yaml
  logging:
    level:
      jacky917.security: DEBUG
  ```

- 日誌**不會輸出 JWT 原文**，但會輸出 authority 清單與請求路徑。
- 每次 401 / 403 都會寫一行 WARN，在流量大或遭受掃描時會產生大量日誌，**正式環境請保持 `false`**。
- 「claim 型態不支援」的 WARN 與此設定無關，一律會輸出。

### `permit-all-patterns` 的寫法

- 使用 Spring Security `requestMatchers(String...)` 的路徑樣式（Spring Security 7 為 `PathPatternRequestMatcher`）：`*` 比對單一區段，`**` 比對多個區段。
- **`**` 只能放在路徑的開頭或結尾**。`/api/**/admin` 這類寫法在 `2.x` 會讓應用程式啟動失敗（`1.x` 可用）。需要時改寫成多個明確的路徑，或自訂 `SecurityFilterChain`。
- 只比對路徑，不區分 HTTP method。
- 設為空清單（`permit-all-patterns: []`）代表所有路徑都需要驗證，包含 health check 與 Swagger。

properties 格式寫法：

```properties
jacky917.security.permit-all-patterns[0]=/public/**
jacky917.security.permit-all-patterns[1]=/actuator/health
# 或以逗號分隔
jacky917.security.permit-all-patterns=/public/**,/actuator/health
```

環境變數寫法（Docker / Kubernetes）：

```bash
JACKY917_SECURITY_PERMITALLPATTERNS_0_=/public/**
JACKY917_SECURITY_PERMITALLPATTERNS_1_=/actuator/health
```

---

## JWT claim 與前綴

| 屬性 | 預設值 | 說明 |
|---|---|---|
| `jacky917.security.jwt.claims.roles` | `roles` | 存放角色的 claim 名稱 |
| `jacky917.security.jwt.claims.permissions` | `permissions` | 存放權限的 claim 名稱 |
| `jacky917.security.jwt.claims.scope` | `scope` | 以**空白**分隔字串存放 scope 的 claim 名稱 |
| `jacky917.security.jwt.claims.scp` | `scp` | 以陣列存放 scope 的 claim 名稱（字串時以**逗號**分隔） |
| `jacky917.security.jwt.prefix.role` | `ROLE_` | 加在角色前的前綴 |
| `jacky917.security.jwt.prefix.permission` | `PERM_` | 加在權限前的前綴 |
| `jacky917.security.jwt.prefix.scope` | `SCOPE_` | 加在 scope 前的前綴（`scope` 與 `scp` 共用） |

### 常見用法

**停用某個 claim 來源**：把 claim 名稱設為空字串。

```yaml
jacky917:
  security:
    jwt:
      claims:
        scp: ""        # 不再讀取 scp
```

**對接使用 `authorities` claim 的 IdP**：

```yaml
jacky917:
  security:
    jwt:
      claims:
        roles: authorities
```

**不加前綴**：把前綴設為空字串。

```yaml
jacky917:
  security:
    jwt:
      prefix:
        permission: ""     # order:read 會直接變成 authority「order:read」
```

> [!WARNING]
> `@RequireRole`、`@RequirePerm`、`@RequireScope` 的前綴是**寫死在註解上的**（`ROLE_` / `PERM_` / `SCOPE_`），不會跟著 `jwt.prefix.*` 改變。修改前綴後，這三個註解會永遠判定失敗（回傳 403）。請改用 `@RequireAny` / `@RequireAll` 並寫完整 authority 名稱，或使用 `@PreAuthorize("hasAuthority('...')")`。

**不支援的情況**：claim 名稱只能指定「頂層」claim，不支援 `realm_access.roles` 這類巢狀路徑。需要時請擴充 `JwtAuthoritiesExtractor`，見 [使用指南 §8.2](getting-started.md#82-自訂-authority-映射例如-keycloak-的-realm_accessroles)。

---

## 與 Spring Boot 原生屬性的關係

### 仍然有效的屬性（決定如何驗證 Token）

Starter 不建立 `JwtDecoder`，以下 Spring Boot 屬性照常生效：

| 屬性 | 用途 |
|---|---|
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | 透過 OIDC Discovery 取得 JWKS，並驗證 `iss` |
| `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` | 直接指定 JWKS 位址 |
| `spring.security.oauth2.resourceserver.jwt.public-key-location` | 使用固定的 RSA 公鑰 |
| `spring.security.oauth2.resourceserver.jwt.jws-algorithms` | 允許的簽章演算法（預設 `RS256`） |
| `spring.security.oauth2.resourceserver.jwt.audiences` | 驗證 `aud` 必須包含其中之一 |

### 不會生效的屬性

Starter 提供自己的 `JwtAuthenticationConverter`，因此 Spring Boot 依下列屬性建立的 converter 不會被建立，這些屬性會**被靜默忽略**：

| 屬性 | 替代做法 |
|---|---|
| `spring.security.oauth2.resourceserver.jwt.authorities-claim-name` | `jacky917.security.jwt.claims.*` |
| `spring.security.oauth2.resourceserver.jwt.authority-prefix` | `jacky917.security.jwt.prefix.*` |
| `spring.security.oauth2.resourceserver.jwt.authorities-claim-delimiter` | 無對應屬性；擴充 `JwtAuthoritiesExtractor` |
| `spring.security.oauth2.resourceserver.jwt.principal-claim-name` | 自訂 `JwtAuthenticationConverter` Bean，見 [使用指南 §8.1](getting-started.md#81-改用-email-作為-principal-名稱) |

### Opaque Token

`spring.security.oauth2.resourceserver.opaquetoken.*` 不受支援。Starter 的 filter chain 固定使用 JWT 模式。

---

## 自動配置的啟用條件

自動配置 `Jacky917SecurityAutoConfiguration` 只在**全部**條件成立時啟用：

| 條件 | 說明 |
|---|---|
| Servlet Web 應用 | WebFlux 與非 Web 應用會略過 |
| `jacky917.security.enabled` 不為 `false` | 預設啟用 |

各個 Bean 另有自己的條件，見 [Starter 設計 — Bean 清單](starter-design.md#自動配置建立的-bean)。
