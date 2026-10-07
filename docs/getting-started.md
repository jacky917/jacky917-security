# 使用指南

本文件說明如何在業務專案（Resource Server）中使用 `jacky917-security-starter`，從引入依賴、設定 Token 驗證、撰寫授權規則，到覆寫預設元件與撰寫測試。

上線前請務必一併閱讀 [限制與注意事項](limitations.md)。

---

## 目錄

1. [引入依賴](#1-引入依賴)
2. [提供 JwtDecoder（必要）](#2-提供-jwtdecoder必要)
3. [設定放行路徑](#3-設定放行路徑)
4. [JWT claims 如何變成 authority](#4-jwt-claims-如何變成-authority)
5. [方法級授權註解](#5-方法級授權註解)
6. [組合條件與 ABAC](#6-組合條件與-abac)
7. [錯誤回應](#7-錯誤回應)
8. [覆寫預設元件](#8-覆寫預設元件)
9. [CORS](#9-cors)
10. [停用 Starter 或部分功能](#10-停用-starter-或部分功能)
11. [撰寫測試](#11-撰寫測試)
12. [上線檢查清單](#12-上線檢查清單)

---

## 1. 引入依賴

前置設定（GitHub Packages 認證、repository）見 [README — 快速開始](../README.md#快速開始業務專案)。

```xml
<dependency>
    <groupId>com.github.jacky917</groupId>
    <artifactId>jacky917-security-starter</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

`jacky917-security-starter` 會帶入：

- `jacky917-security-autoconfigure`（自動配置）
- `jacky917-security-annotations`（`@Require*` 註解）
- `spring-boot-starter-security`、`spring-boot-starter-oauth2-resource-server`

`spring-boot-starter-web` 在 Starter 中是 optional，**業務專案必須自行引入**。Starter 只在 Servlet Web 應用中啟用；若應用不是 Servlet（例如 WebFlux 或非 Web 的批次程式），自動配置會直接略過且不會報錯，Starter 的任何規則（含 `@Require*` 註解）都不會套用。

---

## 2. 提供 JwtDecoder（必要）

Starter 負責「驗證通過之後」的事情（authority 映射、授權、錯誤格式），**不負責決定如何驗證 Token 的簽章**。你必須提供一個 `JwtDecoder`，否則啟動時會失敗：

```
NoSuchBeanDefinitionException: No qualifying bean of type
'org.springframework.security.oauth2.jwt.JwtDecoder' available
```

依你的 Authorization Server 選擇以下其中一種方式。

### 2.1 使用 issuer-uri（推薦，支援 OIDC Discovery 的 IdP）

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com
          audiences: my-api
```

- 啟動後第一次驗證 Token 時，會從 `{issuer-uri}/.well-known/openid-configuration` 探索 JWKS 位址。
- 會自動驗證 `iss`、`exp`、`nbf`。
- 設定 `audiences` 後會額外驗證 `aud`。**強烈建議設定**，否則其他服務的 Token 只要同一個 issuer 簽發，也能打進你的 API。

### 2.2 使用 jwk-set-uri（IdP 不支援 Discovery 時）

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://auth.example.com/oauth2/jwks
          jws-algorithms: RS256
          audiences: my-api
```

> [!WARNING]
> 只設定 `jwk-set-uri` 時，Spring Boot **不會驗證 `iss`**。若需要驗證 issuer，請同時設定 `issuer-uri`，或自訂 `JwtDecoder`（見 2.4）。

### 2.3 使用固定公鑰（離線環境）

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          public-key-location: classpath:keys/auth-public.pem
          audiences: my-api
```

### 2.4 自訂 JwtDecoder Bean（HS256 對稱金鑰、或需要客製驗證規則）

Spring Boot 的屬性不支援 HMAC（HS256）金鑰，這時需要自訂 Bean。以下範例同時驗證 issuer 與 audience：

```java
@Configuration
class JwtDecoderConfig {

    @Bean
    JwtDecoder jwtDecoder(@Value("${app.jwt.secret}") String secret) {
        SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains("my-api"));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer("https://auth.example.com"),
                audience));
        return decoder;
    }
}
```

> [!CAUTION]
> HS256 的金鑰同時可以「驗證」與「簽發」Token。任何拿到這把金鑰的服務都能偽造任意身分的 Token。多服務架構建議改用 RS256 / ES256 等非對稱演算法。HS256 金鑰長度至少需 256 bits（32 bytes）。

`demo-resource-server` 的 [`DemoJwtDecoderConfiguration`](../demo-resource-server/src/main/java/jacky917/demo/resourceserver/config/DemoJwtDecoderConfiguration.java) 是一個從 JWK 檔載入 HS256 金鑰的實際範例（僅驗證 issuer，未驗證 audience，僅供示範）。

---

## 3. 設定放行路徑

除了 `jacky917.security.permit-all-patterns` 列出的路徑，**所有請求都需要有效的 JWT**。

預設值：

```yaml
jacky917:
  security:
    permit-all-patterns:
      - /actuator/health
      - /v3/api-docs
      - /v3/api-docs/**
      - /swagger-ui/**
      - /swagger-ui.html
      - /swagger-ui/index.html
```

> [!IMPORTANT]
> 自訂此屬性會**整個取代**預設清單，不會合併。若你仍需要 Swagger 與 health check，請把它們一起列出。

撰寫規則：

- 使用 Spring 的路徑樣式：`*` 比對單一路徑區段、`**` 比對多個區段。例如 `/public/**` 會放行 `/public/a/b`。
- 規則只比對路徑，**不區分 HTTP method**。需要「GET 放行、POST 需驗證」這類規則時，請自訂 `SecurityFilterChain`（見 §8）。
- 放行路徑上的方法級註解**仍然會生效**。在放行路徑的 Controller 方法加上 `@RequireRole`，匿名呼叫會得到 401。
- 放行路徑上若帶了**無效或過期的** `Authorization: Bearer` 標頭，仍會回傳 401（Spring Security 的 Bearer Token 行為）。前端在呼叫公開 API 時，請不要附上已過期的 Token。

---

## 4. JWT claims 如何變成 authority

驗證通過後，Starter 的 `JwtAuthoritiesExtractor` 會讀取以下 claims，加上前綴後轉為 `GrantedAuthority`：

| Claim（預設名稱） | 接受的格式 | 前綴 | 範例 → 結果 |
|---|---|---|---|
| `roles` | 字串陣列，或**逗號**分隔字串 | `ROLE_` | `["ADMIN"]` → `ROLE_ADMIN` |
| `permissions` | 字串陣列，或**逗號**分隔字串 | `PERM_` | `"order:read,order:write"` → `PERM_order:read`、`PERM_order:write` |
| `scope` | **空白**分隔字串，或字串陣列 | `SCOPE_` | `"openid profile"` → `SCOPE_openid`、`SCOPE_profile` |
| `scp` | 字串陣列，或**逗號**分隔字串 | `SCOPE_` | `["data:read"]` → `SCOPE_data:read` |

處理規則：

- 每個值會先 `trim()`，空白值會被略過；陣列中的 `null` 元素會被略過。
- 所有來源合併後**去重**，並依名稱排序。
- claim 不存在 → 略過，不會報錯。
- claim 型態不是字串或陣列（例如物件）→ 略過，並輸出一行 WARN 日誌。
- 陣列中的非字串元素（例如數字）會以 `toString()` 轉成字串。

claim 名稱與前綴都可以修改，見 [設定參考](configuration.md#jwt-claim-與前綴)。完整的 Token 格式約定見 [JWT Claims 契約](jwt-claims.md)。

在程式中取得目前使用者：

```java
@GetMapping("/me")
Map<String, Object> me(Authentication authentication) {
    String userId = authentication.getName();                     // JWT 的 sub
    Jwt jwt = (Jwt) authentication.getPrincipal();                // 原始 JWT
    String sid = jwt.getClaimAsString("sid");
    return Map.of("userId", userId, "sid", sid);
}

// 或使用 @AuthenticationPrincipal
@GetMapping("/me2")
String me2(@AuthenticationPrincipal Jwt jwt) {
    return jwt.getSubject();
}
```

---

## 5. 方法級授權註解

| 註解 | 檢查內容 | 參數格式 | 範例 | 等同於 |
|---|---|---|---|---|
| `@RequireRole` | 單一角色 | 不含前綴 | `@RequireRole("ADMIN")` | `hasAuthority('ROLE_ADMIN')` |
| `@RequirePerm` | 單一權限 | 不含前綴 | `@RequirePerm("order:read")` | `hasAuthority('PERM_order:read')` |
| `@RequireScope` | 單一 scope | 不含前綴 | `@RequireScope("profile.read")` | `hasAuthority('SCOPE_profile.read')` |
| `@RequireAny` | 任一符合（OR） | **含前綴**，以 `\|` 分隔 | `@RequireAny("ROLE_ADMIN\|PERM_order:read")` | 擁有其中任一個 |
| `@RequireAll` | 全部符合（AND） | **含前綴**，以 `\|` 分隔 | `@RequireAll("ROLE_ADMIN\|PERM_order:write")` | 同時擁有全部 |

### 5.1 放在方法上

```java
@RestController
@RequestMapping("/orders")
class OrderController {

    @RequirePerm("order:read")
    @GetMapping
    List<Order> list() { ... }

    @RequireAny("ROLE_ADMIN|PERM_order:write")
    @PostMapping
    Order create(@RequestBody Order order) { ... }
}
```

### 5.2 放在類別上

```java
@RestController
@RequestMapping("/admin")
@RequireRole("ADMIN")                     // 類別中所有方法都需要 ROLE_ADMIN
class AdminController {

    @GetMapping("/stats")
    Stats stats() { ... }                 // 需要 ROLE_ADMIN

    @RequirePerm("audit:read")
    @GetMapping("/audit")
    List<Audit> audit() { ... }           // ⚠ 只需要 PERM_audit:read，不再檢查 ROLE_ADMIN
}
```

> [!WARNING]
> 方法上有授權註解時，**類別上的註解會被忽略，不會合併**。上例的 `/admin/audit` 只要有 `PERM_audit:read` 即可存取，即使沒有 `ROLE_ADMIN`。需要兩者時請在方法上用 `@RequireAll("ROLE_ADMIN|PERM_audit:read")`。

### 5.3 適用範圍

方法級授權透過 Spring AOP 代理實作，只在以下情況生效：

- 註解所在的類別是 **Spring Bean**（`@RestController`、`@Service`、`@Component` 等）。
- 呼叫是**從 Bean 外部**進來的。同一個類別內 `this.someMethod()` 的自我呼叫不會觸發檢查。

因此註解不只能用在 Controller，也能用在 Service 層：

```java
@Service
class OrderService {
    @RequirePerm("order:delete")
    public void delete(String id) { ... }   // 從其他 Bean 呼叫時才會檢查
}
```

### 5.4 也可以使用 Spring Security 原生註解

Starter 啟用了 `prePostEnabled` 與 `securedEnabled`，以下寫法都可用：

```java
@PreAuthorize("hasRole('ADMIN')")                 // hasRole 會自動補 ROLE_
@PreAuthorize("hasAuthority('PERM_order:read')")  // 權限要寫完整前綴
@PreAuthorize("hasAuthority('SCOPE_profile.read')")
@PostAuthorize("returnObject.ownerId == authentication.name")
@Secured("ROLE_ADMIN")
```

`@RolesAllowed`（JSR-250）**未啟用**。

---

## 6. 組合條件與 ABAC

### 6.1 同一方法只能有一個授權註解

`@Require*` 底層都是 `@PreAuthorize`。同一個方法上放兩個以上（包含與 `@PreAuthorize` 混用），會在**請求進來時**拋出 `AnnotationConfigurationException`，回應 HTTP 500：

```java
// ❌ 執行時錯誤
@RequirePerm("order:read")
@PreAuthorize("@orderSecurity.isOwner(authentication, #id)")
@GetMapping("/orders/{id}")
Order get(@PathVariable String id) { ... }
```

改寫為單一 `@PreAuthorize`：

```java
// ✅
@PreAuthorize("hasAuthority('PERM_order:read') and @orderSecurity.isOwner(authentication, #id)")
@GetMapping("/orders/{id}")
Order get(@PathVariable String id) { ... }
```

### 6.2 ABAC（依資源屬性授權）

以「只有擁有者能讀取」為例：

```java
@Component("orderSecurity")
class OrderSecurity {

    private final OrderRepository orders;

    OrderSecurity(OrderRepository orders) {
        this.orders = orders;
    }

    public boolean isOwner(Authentication authentication, String orderId) {
        if (authentication == null || orderId == null) {
            return false;                                      // 預設拒絕
        }
        return orders.findById(orderId)
                .map(o -> o.getOwnerId().equals(authentication.getName()))
                .orElse(false);                                // 找不到也拒絕
    }
}
```

```java
@PreAuthorize("hasAuthority('PERM_order:read') and @orderSecurity.isOwner(authentication, #orderId)")
@GetMapping("/orders/{orderId}")
Order get(@PathVariable String orderId) { ... }
```

撰寫重點：

- SpEL 中以 `@beanName` 參照 Bean，以 `#參數名` 參照方法參數。參數名稱需要編譯時保留（Spring Boot 的 Maven parent 預設已開啟 `-parameters`）。
- 判斷方法請**預設回傳 `false`**，任何例外狀況（找不到資料、參數為 `null`）都應拒絕。
- 資源不存在時回傳 `false` 會得到 403 而不是 404，這可以避免洩漏「資源是否存在」，但若你的 API 需要 404，請在 Controller 內自行判斷。
- 完整範例見 `demo-resource-server` 的 [`DemoAuthzConfiguration`](../demo-resource-server/src/main/java/jacky917/demo/resourceserver/authz/DemoAuthzConfiguration.java)。

更多授權模型說明見 [授權模型](authorization-model.md)。

---

## 7. 錯誤回應

### 7.1 格式

401 與 403 都會回傳 `application/json`（UTF-8）：

| 欄位 | 說明 |
|---|---|
| `timestamp` | ISO-8601 UTC 時間 |
| `status` | HTTP 狀態碼（`401` / `403`） |
| `errorCode` | HTTP reason phrase（`Unauthorized` / `Forbidden`） |
| `message` | 固定的繁體中文訊息 |
| `path` | 請求路徑（不含 query string） |

```json
{
  "timestamp": "2026-10-07T01:23:45.678Z",
  "status": 403,
  "errorCode": "Forbidden",
  "message": "權限不足，禁止存取",
  "path": "/orders"
}
```

### 7.2 何時回傳 401、何時回傳 403

| 情境 | 狀態碼 | `WWW-Authenticate` 標頭 |
|---|---|---|
| 沒有帶 `Authorization` 標頭 | 401 | `Bearer` |
| Token 格式錯誤、簽章錯誤、過期、`iss` / `aud` 不符 | 401 | `Bearer error="invalid_token", error_description="..."` |
| Token 有效，但不符合方法級授權條件 | 403 | 無 |
| 匿名存取放行路徑上有授權註解的方法 | 401 | `Bearer` |

`WWW-Authenticate` 的 `error_description` 包含驗證失敗的原因（例如 `Jwt expired at ...`），可用於除錯。

### 7.3 限制

- `message` 文字固定，不支援 i18n 或自訂。需要自訂格式時，請自訂 `SecurityFilterChain` 並提供自己的 `AuthenticationEntryPoint` / `AccessDeniedHandler`（見 §8.3）。
- 這兩個 handler 只處理 Spring Security filter chain 與方法級授權拋出的錯誤。若你的 `@RestControllerAdvice` 攔截了 `AccessDeniedException` 或 `Exception`，會**優先於** Starter 的 403 處理，回應格式可能被改變。全域例外處理器請不要攔截 `AccessDeniedException` / `AuthenticationException`，或攔截後重新拋出。

---

## 8. 覆寫預設元件

Starter 的每個 Bean 都有 `@ConditionalOnMissingBean`：只要你定義同型別（或同名稱）的 Bean，預設的就不會建立。

| 你想改的東西 | 定義這個 Bean | 影響 |
|---|---|---|
| claims → authorities 的規則 | `JwtAuthoritiesExtractor`（子類別） | 只替換 authority 映射 |
| principal 名稱、authority 來源 | `JwtAuthenticationConverter` | 取代 Starter 的 converter；預設的 `JwtAuthoritiesExtractor` 仍存在但不會被使用，除非你自行注入 |
| 整個 HTTP 安全規則 | `SecurityFilterChain` | Starter 的 filter chain 完全不建立（放行路徑、JSON 錯誤處理都要自己設） |
| `@RequireAny` / `@RequireAll` 的判斷邏輯 | 名為 `jacky917AuthorityEvaluator` 的 Bean | 以 Bean 名稱判斷，型別可以不同，但要有相同簽章的 `hasAnyAuthority` / `hasAllAuthorities` 方法 |

### 8.1 改用 email 作為 principal 名稱

```java
@Bean
JwtAuthenticationConverter jwtAuthenticationConverter(JwtAuthoritiesExtractor extractor) {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(extractor);   // 保留 Starter 的 authority 映射
    converter.setPrincipalClaimName("email");
    return converter;
}
```

### 8.2 自訂 authority 映射（例如 Keycloak 的 `realm_access.roles`）

```java
@Bean
JwtAuthoritiesExtractor jwtAuthoritiesExtractor(Jacky917SecurityProperties properties) {
    return new JwtAuthoritiesExtractor(properties) {
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<GrantedAuthority> authorities = new ArrayList<>(super.convert(jwt));
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
                roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
            }
            return authorities;
        }
    };
}
```

> 內建的 extractor 只讀取「頂層」claim，不支援 `realm_access.roles` 這類巢狀路徑，所以需要像上面這樣擴充。

### 8.3 自訂 SecurityFilterChain

當你需要 HTTP method 層級的規則、多條 filter chain、或自訂錯誤格式時：

```java
@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception {
        http
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/products/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        return http.build();
    }
}
```

此時：

- `jacky917.security.permit-all-patterns` **不再生效**。
- 401 / 403 回到 Spring Security 預設行為（無 JSON body），除非你自行設定 `authenticationEntryPoint` 與 `accessDeniedHandler`。若要 401 也走 JSON，請同時設定在 `oauth2ResourceServer(...)` 與 `exceptionHandling(...)` 上。
- 注入 Starter 提供的 `JwtAuthenticationConverter` 可沿用 authority 映射，`@Require*` 註解照常可用。

---

## 9. CORS

Starter **不設定 CORS**。瀏覽器前端直接呼叫 API 時，需要提供 `CorsConfigurationSource` Bean。由於 Starter 的 filter chain 沒有呼叫 `http.cors()`，建議以自訂 `SecurityFilterChain`（§8.3）加上 `.cors(Customizer.withDefaults())`，或在 API Gateway 層處理 CORS。

若只在 Spring MVC 設定 `WebMvcConfigurer#addCorsMappings`，瀏覽器的 preflight（`OPTIONS`）請求可能先被 Spring Security 以 401 擋下。

---

## 10. 停用 Starter 或部分功能

```yaml
jacky917:
  security:
    enabled: false               # 停用整個自動配置
    method-security:
      enabled: false             # 只停用方法級授權（@PreAuthorize、@Require* 都不會生效）
```

- `enabled: false` 時，Starter 的 filter chain、converter、evaluator 都不會建立，應用回到 Spring Boot 原生行為（若有設定 `spring.security.oauth2.resourceserver.jwt.*`，Boot 會建立它自己的 Resource Server 設定）。
- `method-security.enabled: false` 時，若業務專案自己另外加了 `@EnableMethodSecurity`，方法級授權仍會啟用。
- 停用方法級授權後，`@Require*` 註解**不會報錯，而是靜默失效**，請確認這是你要的結果。

---

## 11. 撰寫測試

加入測試依賴：

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

### 11.1 直接指定 authorities（最常用）

```java
@SpringBootTest
@AutoConfigureMockMvc
class OrderControllerTest {

    @Autowired MockMvc mockMvc;

    @Test
    void readOrderRequiresPermission() throws Exception {
        mockMvc.perform(get("/orders")
                        .with(jwt().authorities(new SimpleGrantedAuthority("PERM_order:read"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/orders")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }
}
```

`jwt()` 來自 `SecurityMockMvcRequestPostProcessors`，會略過 `JwtDecoder`，所以測試不需要真的簽發 Token，也不需要連線到 Authorization Server。

### 11.2 透過 claims 測試（同時驗證 authority 映射）

`.authorities(...)` 會跳過 Starter 的 claims 映射。若要確認 Token 的 claims 能被正確轉換，改傳入 extractor：

```java
@Autowired JwtAuthoritiesExtractor extractor;

@Test
void rolesClaimIsMapped() throws Exception {
    mockMvc.perform(get("/admin/stats")
                    .with(jwt()
                            .jwt(j -> j.subject("alice").claim("roles", List.of("ADMIN")))
                            .authorities(extractor)))
            .andExpect(status().isOk());
}
```

### 11.3 測試環境沒有 Authorization Server

`@SpringBootTest` 會啟動完整 context，仍需要 `JwtDecoder`。若正式設定使用 `issuer-uri` 而測試環境連不到 IdP，有兩種做法：

- `issuer-uri` 只在第一次驗證 Token 時才連線，用 `jwt()` 的測試不會觸發，通常可以直接跑。
- 或在測試設定中提供一個 mock `JwtDecoder` Bean。這個做法適用於正式環境以「屬性」設定 decoder 的情況；若正式環境本來就自訂了 `JwtDecoder` Bean，兩者會衝突，請改用 `@MockitoBean JwtDecoder jwtDecoder;` 取代。

```java
@TestConfiguration
class TestJwtConfig {
    @Bean
    JwtDecoder jwtDecoder() {
        return token -> { throw new BadJwtException("tests must use jwt() post processor"); };
    }
}
```

---

## 12. 上線檢查清單

- [ ] 已提供 `JwtDecoder`，並驗證 `iss`、`aud`、`exp`
- [ ] 使用非對稱簽章演算法（RS256 / ES256）；若使用 HS256，金鑰不在原始碼或映像檔中
- [ ] `permit-all-patterns` 只包含真正公開的路徑；正式環境是否仍需放行 Swagger
- [ ] 沒有任何方法同時放了兩個授權註解（見 [限制 §1](limitations.md#1-同一個方法只能有一個授權註解)）
- [ ] 類別層級與方法層級的註解沒有錯誤地期待「合併」（見 §5.2）
- [ ] 若修改過 `jacky917.security.jwt.prefix.*`，沒有使用 `@RequireRole` / `@RequirePerm` / `@RequireScope`（見 [限制 §3](limitations.md#3-單一條件註解的前綴固定)）
- [ ] 全域例外處理器沒有吞掉 `AccessDeniedException`
- [ ] 瀏覽器前端需要時，已設定 CORS
- [ ] `jacky917.security.debug-log` 在正式環境為 `false`
