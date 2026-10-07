# 限制與注意事項

本文件列出 `jacky917-security-resource-server-starter`（2.x）已知的限制，以及容易誤用的行為。每一項都附上「會發生什麼事」與「該怎麼做」。

標示 🧪 的項目已有自動化測試驗證，見 [`SecurityBehaviorIntegrationTest`](../../resource-server/jacky917-security-resource-server-autoconfigure/src/test/java/jacky917/security/resourceserver/autoconfigure/integration/SecurityBehaviorIntegrationTest.java)。

---

## 速查表

| # | 限制 | 嚴重度 | 何時發現 |
|---|---|---|---|
| 1 | [同一個方法只能有一個授權註解](#1-同一個方法只能有一個授權註解) | 🔴 高 | 請求進來時（HTTP 500） |
| 2 | [類別與方法的註解不會合併](#2-類別與方法的註解不會合併) | 🔴 高 | 不會發現（權限比預期寬鬆） |
| 3 | [單一條件註解的前綴固定](#3-單一條件註解的前綴固定20-已解決) | ✅ 2.0 已解決 | — |
| 4 | [必須自行提供 JwtDecoder](#4-必須自行提供-jwtdecoder) | 🟠 中 | 啟動時 |
| 5 | [Spring Boot 原生的 JWT converter 屬性無效](#5-spring-boot-原生的-jwt-converter-屬性無效) | 🟠 中 | 不會發現（屬性被忽略） |
| 6 | [Token 無法撤銷](#6-token-無法撤銷) | 🟠 中 | 設計限制 |
| 7 | [Starter 本身不驗證 aud](#7-starter-本身不驗證-aud) | 🟠 中 | 設計限制 |
| 8 | [放行路徑的行為](#8-放行路徑的行為) | 🟡 低 | 請求進來時 |
| 9 | [`@RequireAny` / `@RequireAll` 的參數限制](#9-requireany--requireall-的參數限制) | 🟡 低 | 請求進來時 |
| 10 | [方法級授權只對 Spring Bean 的外部呼叫生效](#10-方法級授權只對-spring-bean-的外部呼叫生效) | 🟡 低 | 不會發現 |
| 11 | [claims 解析的限制](#11-claims-解析的限制) | 🟡 低 | 不會發現（authority 缺少） |
| 12 | [錯誤回應的限制](#12-錯誤回應的限制) | 🟡 低 | 設計限制 |
| 13 | [自訂 SecurityFilterChain 會讓整條 chain 讓位](#13-自訂-securityfilterchain-會讓整條-chain-讓位) | 🟡 低 | 設計限制 |
| 14 | [停用方法級授權時註解靜默失效](#14-停用方法級授權時註解靜默失效20-已解決) | ✅ 2.0 已解決 | — |
| 15 | [支援範圍](#15-支援範圍) | — | — |
| 16 | [發佈與依賴](#16-發佈與依賴) | 🟠 中 | 引入依賴時 |
| 17 | [新舊座標同時存在](#17-新舊座標同時存在) | 🟠 中 | 不會發現（授權結果取決於 classpath 順序） |
| 18 | [無法只關閉 Starter 的方法級授權](#18-無法只關閉-starter-的方法級授權) | 🟡 低 | 啟動時或請求進來時 |

---

## 1. 同一個方法只能有一個授權註解

🧪 **會發生什麼事**

`@RequireRole`、`@RequirePerm`、`@RequireScope`、`@RequireAny`、`@RequireAll` 都是以 `@PreAuthorize` 作為 meta-annotation 實作。Spring Security 規定同一個方法上只能找到**一個** `@PreAuthorize`，因此以下寫法在**編譯與啟動時都不會報錯**，而是在第一次呼叫時拋出 `AnnotationConfigurationException`，回應 HTTP 500：

```java
@RequirePerm("order:read")
@RequireRole("ADMIN")                                         // ❌ 兩個 @Require*
@GetMapping("/a") String a() { ... }

@RequirePerm("order:read")
@PreAuthorize("@orderSecurity.isOwner(authentication, #id)")  // ❌ @Require* + @PreAuthorize
@GetMapping("/b/{id}") String b(@PathVariable String id) { ... }
```

錯誤訊息類似：

```
Please ensure there is one unique annotation of type @PreAuthorize attributed to ...
Found 2 competing annotations: [...]
```

**該怎麼做**

- 多個 authority 的 AND / OR：改用 `@RequireAll` / `@RequireAny`。
- 需要搭配 ABAC 或其他 SpEL：全部寫在同一個 `@PreAuthorize`：

  ```java
  @PreAuthorize("hasAuthority('PERM_order:read') and @orderSecurity.isOwner(authentication, #id)")
  ```

- 每個受保護的端點都要有整合測試實際打一次，才能在上線前發現這個問題。

---

## 2. 類別與方法的註解不會合併

🧪 **會發生什麼事**

方法上有授權註解時，類別上的授權註解會被**完全忽略**，而不是兩者都要符合：

```java
@RestController
@RequireRole("ADMIN")
class AdminController {

    @RequirePerm("audit:read")
    @GetMapping("/admin/audit")
    List<Audit> audit() { ... }     // 只檢查 PERM_audit:read，沒有 ROLE_ADMIN 也能存取
}
```

這不會產生任何錯誤，只會讓權限**比預期寬鬆**，是本清單中最危險的一項。

**該怎麼做**

在方法上寫出完整條件：`@RequireAll("ROLE_ADMIN|PERM_audit:read")`。若類別上有授權註解，方法上就不要再放，或者明確地在方法上把類別的條件也寫進去。

---

## 3. 單一條件註解的前綴固定（2.0 已解決）

> ✅ **2.0 起已解決**：這三個註解改為使用 `jacky917.security.jwt.prefix.*` 設定的前綴（[設定參考](configuration.md#jwt-claim-與前綴)）。以下內容只適用於 **1.x**。

**會發生什麼事（1.x）**

`@RequireRole`、`@RequirePerm`、`@RequireScope` 的前綴寫死在註解定義中：

| 註解 | 實際檢查 |
|---|---|
| `@RequireRole("X")` | `hasAuthority('ROLE_X')` |
| `@RequirePerm("X")` | `hasAuthority('PERM_X')` |
| `@RequireScope("X")` | `hasAuthority('SCOPE_X')` |

若你修改了 `jacky917.security.jwt.prefix.*`，Token 映射出的 authority 會用新前綴，但這三個註解仍檢查舊前綴，結果是**永遠 403**。

**該怎麼做（1.x）**

修改前綴時，改用 `@RequireAny` / `@RequireAll`（參數寫完整 authority 名稱），或使用 `@PreAuthorize("hasAuthority('...')")`；或升級到 2.0。

---

## 4. 必須自行提供 JwtDecoder

🧪 **會發生什麼事**

Starter 不會建立 `JwtDecoder`。沒有提供時，應用程式啟動失敗：

```
NoSuchBeanDefinitionException: No qualifying bean of type
'org.springframework.security.oauth2.jwt.JwtDecoder' available
```

**該怎麼做**

設定 `spring.security.oauth2.resourceserver.jwt.issuer-uri`（或 `jwk-set-uri`、`public-key-location`），或自訂 `JwtDecoder` Bean。見 [使用指南 §2](getting-started.md#2-提供-jwtdecoder必要)。

---

## 5. Spring Boot 原生的 JWT converter 屬性無效

🧪 **會發生什麼事**

Starter 提供自己的 `JwtAuthenticationConverter`，而 Spring Boot 只會在沒有這個 Bean 時才依屬性建立 converter。因此以下屬性會**被靜默忽略**，不會有任何警告：

- `spring.security.oauth2.resourceserver.jwt.principal-claim-name`
- `spring.security.oauth2.resourceserver.jwt.authorities-claim-name`
- `spring.security.oauth2.resourceserver.jwt.authorities-claim-delimiter`
- `spring.security.oauth2.resourceserver.jwt.authority-prefix`

`authentication.getName()` 固定是 JWT 的 `sub`。

**該怎麼做**

authority 相關設定改用 `jacky917.security.jwt.*`；principal 名稱需要自訂 `JwtAuthenticationConverter` Bean。見 [設定參考](configuration.md#不會生效的屬性)。

---

## 6. Token 無法撤銷

**會發生什麼事**

JWT 驗證是無狀態的：只要簽章正確且未過期，Token 就有效。Starter **不會**查詢資料庫或快取來確認 Token 是否已被撤銷，也**不會**檢查 `sid`、`jti`。使用者登出、帳號被停用或權限被移除後，舊的 Access Token 在到期前仍然可以使用，Token 裡的 roles / permissions 也仍然是簽發當時的內容。

**該怎麼做**

- 將 Access Token 有效期縮短（建議 5～15 分鐘），搭配 Refresh Token Rotation，見 [Refresh Token Rotation](../design/refresh-rotation.md)。
- 對高風險操作（刪除、付款、權限變更），在業務邏輯中即時查詢使用者狀態，不要只依賴 Token 內的 authority。
- 需要即時撤銷時，自訂 `JwtDecoder` 並加入一個查詢黑名單（例如以 `jti` 或 `sid` 為 key 的 Redis）的 `OAuth2TokenValidator`。

---

## 7. Starter 本身不驗證 aud

**會發生什麼事**

Token 的驗證規則完全由你提供的 `JwtDecoder` 決定。Starter 不會另外檢查 `aud`。若 `JwtDecoder` 沒有設定 audience 驗證，**同一個 Authorization Server 簽發給其他服務的 Token，也能存取你的 API**。

另外，只設定 `jwk-set-uri`（沒有 `issuer-uri`）時，Spring Boot 不會驗證 `iss`。

**該怎麼做**

設定 `spring.security.oauth2.resourceserver.jwt.audiences`，或在自訂 `JwtDecoder` 中加入 audience validator。見 [使用指南 §2](getting-started.md#2-提供-jwtdecoder必要)。

---

## 8. 放行路徑的行為

🧪 **會發生什麼事**

| 情境 | 結果 |
|---|---|
| 放行路徑，不帶 Token | 200 |
| 放行路徑，帶**無效或過期**的 Token | **401**（不會當作匿名放行） |
| 放行路徑，方法上有 `@Require*` 且未帶 Token | 401 |
| 自訂 `permit-all-patterns` | **取代**預設清單（`/actuator/health` 不再放行） |
| 預設清單 | 只有 `/actuator/health`；Swagger／OpenAPI 需自行加入（1.x 預設會放行） |
| 想要「GET 放行、POST 需驗證」 | 無法用 `permit-all-patterns` 表達 |
| `**` 放在路徑中間（例如 `/api/**/admin`） | `2.x`：**啟動失敗**（Spring Security 7 的路徑比對規則） |

**該怎麼做**

- 前端呼叫公開 API 時不要附上已過期的 Token，或在 401 時清除 Token 後重試。
- 自訂 `permit-all-patterns` 時，把仍需要的預設路徑一起列出。
- 需要依 HTTP method 區分時，自訂 `SecurityFilterChain`，見 [使用指南 §8.3](getting-started.md#83-自訂-securityfilterchain)。

---

## 9. `@RequireAny` / `@RequireAll` 的參數限制

**會發生什麼事**

- 參數必須是**完整 authority 名稱**（含 `ROLE_` / `PERM_` / `SCOPE_` 前綴），只能以 `|` 分隔。
- 參數值會被插入 SpEL 字串常值中，**不可包含單引號 `'`**，否則會在呼叫時產生 SpEL 解析錯誤。
- 每個項目會被 `trim()`；空白項目會被忽略。
- 若沒有任何有效項目（例如 `""`、`"|"`、`" | "`），一律拒絕存取。
- 參數是註解屬性，只能是編譯期常數，無法從設定檔或資料庫動態讀取。

**該怎麼做**

需要動態的權限規則時，改用 `@PreAuthorize` 呼叫自訂 Bean。

---

## 10. 方法級授權只對 Spring Bean 的外部呼叫生效

**會發生什麼事**

方法級授權以 Spring AOP 代理實作：

- 非 Spring Bean（自己 `new` 出來的物件）上的註解不會生效。
- 同一個類別內的自我呼叫（`this.deleteOrder(id)`）不會經過代理，**不會檢查**。
- `private` 方法上的註解不會生效。

**該怎麼做**

把需要保護的方法放在 Controller 或另一個 Service Bean 的 `public` 方法上，並從外部呼叫。

---

## 11. claims 解析的限制

**會發生什麼事**

- 只支援**頂層** claim，不支援 `realm_access.roles`（Keycloak）、`resource_access.<client>.roles` 這類巢狀路徑。
- 字串格式的 `roles`、`permissions`、`scp` 以**逗號**分隔，`scope` 以**空白**分隔，無法修改分隔符號。
- 型態不是字串或陣列的 claim（例如物件）會被略過，只留下一行 WARN 日誌，不會讓驗證失敗。

**該怎麼做**

擴充 `JwtAuthoritiesExtractor`，見 [使用指南 §8.2](getting-started.md#82-自訂-authority-映射例如-keycloak-的-realm_accessroles)。

---

## 12. 錯誤回應的限制

🧪 **會發生什麼事**

- `message` 文字固定為繁體中文（`未經驗證，無法存取資源` / `權限不足，禁止存取`），不支援 i18n 或自訂。
- `1.x`：回應 JSON 使用 Starter 內部的 `ObjectMapper`，不受 `spring.jackson.*` 設定影響。`2.x` 起改用應用程式的 Jackson 3 `JsonMapper`，`spring.jackson.*` 會生效（有多個 `JsonMapper` bean 時使用預設設定）。
- 回應不包含失敗原因（例如「Token 已過期」）。401 的原因只會出現在 `WWW-Authenticate` 標頭的 `error_description`。
- 若業務專案的 `@RestControllerAdvice` 攔截了 `AccessDeniedException` 或 `Exception`，方法級授權失敗會被它處理，**不會**回傳 Starter 的 403 JSON。

**該怎麼做**

- 需要自訂格式時，自訂 `SecurityFilterChain` 並提供自己的 `AuthenticationEntryPoint` 與 `AccessDeniedHandler`。
- 全域例外處理器不要攔截 `AccessDeniedException`、`AuthenticationException`，或攔截後重新拋出。

---

## 13. 自訂 SecurityFilterChain 會讓整條 chain 讓位

**會發生什麼事**

只要應用程式中存在任何 `SecurityFilterChain` Bean，Starter 的 filter chain 就**完全不會建立**，以下功能一起失效：

- `jacky917.security.permit-all-patterns`
- 401 / 403 JSON 回應
- STATELESS 與 CSRF 停用設定

仍然保留的是：`JwtAuthenticationConverter`（authority 映射）、方法級授權、`@Require*` 註解。

**該怎麼做**

自訂 filter chain 時注入 Starter 的 `JwtAuthenticationConverter`，並自行補上需要的設定。範本見 [使用指南 §8.3](getting-started.md#83-自訂-securityfilterchain)。

---

## 14. 停用方法級授權時註解靜默失效（2.0 已解決）

> ✅ **2.0 起已解決**：`jacky917.security.method-security.enabled` 已移除，方法級授權在 Starter 啟用時一律開啟。以下內容只適用於 **1.x**。

**會發生什麼事（1.x）**

設定 `jacky917.security.method-security.enabled=false` 後，`@PreAuthorize`、`@Require*` 等註解**不會報錯，也不會檢查**，所有已驗證的使用者都能存取。

反過來說，業務專案若自行加了 `@EnableMethodSecurity`，即使該屬性為 `false`，方法級授權仍會啟用。

**該怎麼做（1.x）**

除非你很確定，否則不要停用方法級授權；或升級到 2.0。

---

## 15. 支援範圍

| 項目 | 支援 |
|---|---|
| Servlet（Spring MVC） | ✅ |
| WebFlux（Reactive） | ❌ 自動配置會略過，所有 Starter 規則都不套用（`@Require*` 所需的 Bean 仍會註冊，自行啟用方法級授權即可使用註解） |
| JWT（JWS 簽章） | ✅ |
| JWE（加密 JWT） | ❌ 需自訂 `JwtDecoder` |
| Opaque Token / Introspection | ❌ |
| 多個 issuer（multi-tenant） | ❌ 需自訂 filter chain 與 `AuthenticationManagerResolver` |
| CORS | ❌ 不設定，見 [使用指南 §9](getting-started.md#9-cors) |
| `@RolesAllowed`（JSR-250） | ❌ 未啟用 |
| Token 簽發、Refresh Token | ❌ 屬於 Authorization Server 的責任 |

---

## 16. 發佈與依賴

**會發生什麼事**

- 套件發佈在 GitHub Packages，**即使是公開套件也必須以 PAT 認證**才能下載。
- `1.0.0` 的 parent POM 繼承自 `spring-boot-starter-parent:3.5.10-SNAPSHOT`，解析依賴時需要存取 Spring Snapshot repository，在企業 Maven mirror 或離線環境中常會失敗。`1.1.0` 起改為 `3.5.16` 正式版，`2.x` 為 `4.1.1` 正式版。
- 1.x 的模組依賴 `jacky917-security-parent`，若發佈流程漏掉 parent，消費端會遇到 `jacky917-security-parent:pom` 找不到的錯誤。2.x 發佈的是不含 parent 的獨立 POM（`flatten-maven-plugin`），沒有這個問題。
- 2.x 的座標改為 `io.github.jacky917`（見 [升級到 2.0](../guides/upgrade-to-2.0.md)）。

**該怎麼做**

見 [GitHub Packages](../guides/github-packages.md) 與 [疑難排解](troubleshooting.md#could-not-find-artifact--jacky917-security-parent)。

---

## 17. 新舊座標同時存在

**會發生什麼事**

2.0 只為 starter 提供 relocation（`com.github.jacky917:jacky917-security-starter` → 新座標）。`jacky917-security-annotations` 與 `jacky917-security-autoconfigure` 的舊座標**沒有** relocation。

若專案中某個模組（例如共用的 domain 函式庫）仍直接依賴 `com.github.jacky917:jacky917-security-annotations:1.x`，而應用程式改用 2.0 的 starter，classpath 上會同時出現新舊兩份 `jacky917.security.annotations.*`。Maven 只會在**相同 groupId:artifactId** 之間選版本，不同 groupId 不會互相取代，所以不會有任何警告。

實際使用哪一份由 classpath 順序決定。若用到舊版，`@RequireRole` 等註解會使用 1.x 寫死的 `ROLE_`／`PERM_`／`SCOPE_` 前綴；有修改 `jwt.prefix.*` 時，授權結果會與預期不同。

**該怎麼做**

- 所有模組一起改用 `io.github.jacky917` 的座標，建議以 BOM 管理版本。
- 檢查是否還有舊座標：

```bash
mvn dependency:tree -Dincludes=com.github.jacky917
```

  除了 relocation 本身（`jacky917-security-starter`）以外，不應該出現任何結果。

---

## 18. 無法只關閉 Starter 的方法級授權

**會發生什麼事**

2.0 移除了 `jacky917.security.method-security.enabled`：Starter 啟用時一律以 `@EnableMethodSecurity(securedEnabled = true)` 開啟方法級授權（原因見 [§14](#14-停用方法級授權時註解靜默失效20-已解決)）。

應用程式若自行設定了不同的方法級授權（例如 `@EnableMethodSecurity(mode = AdviceMode.ASPECTJ)`），會與 Starter 的設定同時存在，授權檢查可能重複執行或設定不一致。

**該怎麼做**

改為停用整個 Starter（`jacky917.security.enabled=false`），自行設定 filter chain 與方法級授權。`@Require*` 註解所需的 Bean 在停用後仍會註冊，註解可以照常使用，見 [使用指南 §10](getting-started.md#10-停用-starter)。
