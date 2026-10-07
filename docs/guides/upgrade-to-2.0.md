# 從 1.x 升級到 2.0

2.0 是破壞性升級：底層從 Spring Boot 3.5 換成 **Spring Boot 4.1**，Maven 座標與部分設定也一併調整。本文件依「必須做」與「需要確認」列出所有變更。

> 不打算升級 Spring Boot 的專案，可以繼續使用 `1.x`（只提供安全修補，見 [`1.x` 分支](https://github.com/jacky917/jacky917-security-starter/tree/1.x)）。

---

## 1. 前提

| 項目 | 1.x | 2.0 |
|---|---|---|
| Spring Boot | 3.5.x | **4.1.x** |
| Spring Security | 6.5.x | 7.1.x |
| Java | 21 以上 | 21 以上 |

請先依 [Spring Boot 4.0 Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide) 把應用程式升到 Spring Boot 4.1，再升級本 starter。與本 starter 直接相關的 Spring Boot 4 變更：

| 變更 | 做法 |
|---|---|
| `spring-boot-starter-web` 改名 | 改用 `spring-boot-starter-webmvc`（舊名稱已棄用） |
| 測試依賴模組化 | 改用 `spring-boot-starter-security-test` 與 `spring-boot-starter-webmvc-test` |
| `@AutoConfigureMockMvc` 搬家 | `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc` |
| 預設使用 Jackson 3 | 套件名稱由 `com.fasterxml.jackson` 改為 `tools.jackson` |

---

## 2. 必須做的變更

### 2.1 Maven 座標

| | 1.x | 2.0 |
|---|---|---|
| groupId | `com.github.jacky917` | **`io.github.jacky917`** |
| Starter | `jacky917-security-starter` | **`jacky917-security-resource-server-starter`** |
| 自動配置 | `jacky917-security-autoconfigure` | `jacky917-security-resource-server-autoconfigure` |
| 註解 | `jacky917-security-annotations` | `jacky917-security-annotations`（不變） |
| 新增 | — | `jacky917-security-core`（由 starter 帶入）、`jacky917-security-bom` |

建議改用 BOM：

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.github.jacky917</groupId>
            <artifactId>jacky917-security-bom</artifactId>
            <version>2.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.github.jacky917</groupId>
        <artifactId>jacky917-security-resource-server-starter</artifactId>
    </dependency>
</dependencies>
```

> **過渡期**：2.0.x 仍會發佈舊座標 `com.github.jacky917:jacky917-security-starter`，它只是一個 relocation，Maven 會自動導向新座標並顯示改名提示。所以只把版本號改成 2.0.x 也能運作，但請盡快改用新座標；3.0 會移除這個 relocation。

### 2.2 Java 套件（只影響有直接使用自動配置類別的專案）

| 1.x | 2.0 |
|---|---|
| `jacky917.security.autoconfigure.*` | `jacky917.security.resourceserver.autoconfigure.*` |
| `jacky917.security.annotations.*` | 不變 |

常見的受影響情況：擴充 `JwtAuthoritiesExtractor`、注入 `Jacky917SecurityProperties`、自訂 `Jacky917AuthorityEvaluator`。只使用 `@Require*` 註解的專案不受影響。

### 2.3 自訂 `jacky917AuthorityEvaluator` 的專案

`@RequireRole`／`@RequirePerm`／`@RequireScope` 改為呼叫 evaluator 的新方法。若你以同名 Bean 取代了預設的 evaluator，必須補上：

```java
public boolean hasRole(Authentication authentication, String role) { ... }
public boolean hasPerm(Authentication authentication, String permission) { ... }
public boolean hasScope(Authentication authentication, String scope) { ... }
```

否則這三個註解會在呼叫時拋出 SpEL 例外（HTTP 500）。

---

## 3. 設定屬性的變更

| 屬性 | 2.0 | 要做的事 |
|---|---|---|
| `jacky917.security.permit-all-patterns` | **預設只有 `/actuator/health`**（1.x 預設還包含 Swagger／OpenAPI） | 需要公開 Swagger 時自行加入 `/v3/api-docs`、`/v3/api-docs/**`、`/swagger-ui/**`、`/swagger-ui.html` |
| `jacky917.security.debug-log` | **已移除** | 改用 `logging.level.jacky917.security: DEBUG` |
| `jacky917.security.method-security.enabled` | **已移除**（方法級授權一律開啟） | 刪除此設定。若原本設為 `false`，升級後註解會開始生效 |
| 其他（`enabled`、`jwt.*`） | 不變 | — |

Spring Boot 會忽略已移除的屬性，留在設定檔中不會報錯，但也不再有作用，建議刪除以免誤會。

`permit-all-patterns` 中 `**` 只能放在路徑的**開頭或結尾**（Spring Security 7 的路徑比對規則），`/api/**/admin` 這類寫法會讓應用程式**啟動失敗**。

---

## 4. 行為變更（需要確認）

| 變更 | 影響 | 對策 |
|---|---|---|
| `@RequireRole`／`@RequirePerm`／`@RequireScope` **跟隨 `jwt.prefix.*`** | 有修改前綴的專案：1.x 這三個註解永遠 403，2.0 起正確判斷 | 確認權限設定符合預期 |
| 單一條件註解的值為空白時一律拒絕 | `@RequireRole("")` 之類的寫法一律 403 | 通常不會有人這樣寫 |
| 401／403 的 JSON 改用應用程式的 Jackson 設定 | 有設定 `spring.jackson.*` 時，錯誤回應的格式會跟著改變（例如縮排、日期格式） | 檢查前端是否依賴固定格式 |
| 401 的 `WWW-Authenticate` 多了 `resource_metadata`（RFC 9728），並自動提供 `/.well-known/oauth-protected-resource` | 完整比對標頭內容的客戶端需要調整 | 改為檢查開頭的 `Bearer` |
| `Authentication` 多了 `FACTOR_BEARER` authority（Spring Security 7） | 列出或比對完整 authority 清單的程式會看到多一項 | 以「是否包含」判斷，不要比對整個清單 |
| 401／403 的日誌改為 DEBUG（1.x 開啟 `debug-log` 時為 WARN） | 原本依賴 WARN 日誌監控 401／403 的告警會收不到 | 改以 metrics 或 access log 監控 |

`@Secured` **仍然支援**，不需要修改。

---

## 5. 測試

| 1.x | 2.0 |
|---|---|
| `spring-boot-starter-test` + `spring-security-test` | `spring-boot-starter-security-test` + `spring-boot-starter-webmvc-test` |
| `org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc` | `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc` |

`SecurityMockMvcRequestPostProcessors.jwt()` 的用法不變。

---

## 6. 升級檢查清單

- [ ] 應用程式已升級到 Spring Boot 4.1，並改用 `spring-boot-starter-webmvc`
- [ ] 依賴改為 `io.github.jacky917:jacky917-security-resource-server-starter`（或匯入 `jacky917-security-bom`）
- [ ] 有 import `jacky917.security.autoconfigure.*` 的程式已改為 `jacky917.security.resourceserver.autoconfigure.*`
- [ ] 自訂的 `jacky917AuthorityEvaluator` 已補上 `hasRole`、`hasPerm`、`hasScope`
- [ ] 需要公開的 Swagger／OpenAPI 路徑已加入 `permit-all-patterns`
- [ ] 已刪除 `debug-log`、`method-security.enabled`，日誌改用 `logging.level`
- [ ] `permit-all-patterns` 沒有 `**` 在中間的寫法
- [ ] 測試依賴與 `@AutoConfigureMockMvc` 的 import 已更新
- [ ] 確認前端與監控不依賴 401 標頭的完整內容、錯誤 JSON 的固定格式、WARN 等級的 401／403 日誌
