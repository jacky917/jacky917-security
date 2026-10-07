# Spring Boot 4.1 升級設計

| 項目 | 內容 |
|---|---|
| 狀態 | ✅ M1 已實施（分支 `claude/spring-boot-4.1-upgrade`），見 [§9 實施結果](#9-實施結果) |
| 日期 | 2026-10-07 |
| 目標 | 將全部模組由 Spring Boot `3.5.10-SNAPSHOT` 升級到 **Spring Boot 4.1.1** |
| 上層文件 | [2.0 總設計](v2-overview.md) |
| 相關文件 | [Repo 拆分設計](repo-structure-design.md)、[Authorization Server 設計](auth-server-design.md) |

本文件中的版本號、artifact 名稱與類別位置，皆已於 2026-10-07 對 Maven Central 上的 Spring Boot 4.1.1 與 Spring Security 7.1.1 實際檢查。

---

## 1. 為什麼要升級

| 原因 | 說明 |
|---|---|
| **3.5 已停止支援** | Spring Boot 3.5 的開源支援已於 2026-06-30 結束，之後的安全性修補只有付費方案才有 |
| **目前使用 SNAPSHOT** | parent 是 `3.5.10-SNAPSHOT`，比 3.x 的最終版 3.5.16 落後 6 個修補版本，而且讓使用者必須存取 Spring 的 SNAPSHOT repository |
| **Auth Server 的前提** | Spring Authorization Server 已併入 Spring Security 7，新功能只會出現在 7.x |
| **時效** | 4.0 的支援到 2026-12 結束；4.1 的支援到 **2027-07** |

### 為什麼選 4.1.1，而不是 4.0 或 4.2

| 版本 | 狀態 | 評估 |
|---|---|---|
| 4.0.8 | 支援到 2026-12 | 2 個月後就要再升級 ❌ |
| **4.1.1** | **目前最新正式版**，支援到 2027-07 | ✅ |
| 4.2.0-M2 | 預覽版，預計 2026-11 正式發佈 | 不可用於正式發佈的函式庫 ❌ |

4.2 正式發佈後，從 4.1 升到 4.2 屬於小版本升級，另行處理即可。

---

## 2. 版本對照

| 依賴 | 目前（Boot 3.5） | 升級後（Boot 4.1.1） | 備註 |
|---|---|---|---|
| Spring Boot | 3.5.10-SNAPSHOT | **4.1.1** | |
| Spring Framework | 6.2.x | **7.0.9** | |
| Spring Security | 6.5.x | **7.1.1** | 已內含 Authorization Server |
| Jackson | 2.x | **3.1.5**（`tools.jackson`） | 套件名稱改變；2.x 仍可透過已棄用的相容模組使用 |
| Hibernate | 6.x | **7.4.5** | 只影響 demo |
| JUnit | 5.x | **6.0.3** | Jupiter API 的套件名稱不變 |
| Lombok | Boot 管理 | 1.18.46 | |
| H2 | Boot 管理 | 2.4.240 | 只用於測試 |
| MySQL Connector/J | Boot 管理 | 9.7.0 | 只影響 demo |
| Testcontainers | 未使用 | 2.0.5 | Auth Server 測試會用到 |
| springdoc-openapi | 2.8.13 | **3.1.1** | 3.x 才支援 Boot 4；只影響 demo |
| Java | 21 | **21**（不變） | Boot 4.1 支援 Java 17～26 |

---

## 3. 影響清單

依「一定要改（不改就編譯或啟動失敗）」與「建議一起改」分類。

### 3.1 一定要改

| # | 變更 | 影響檔案 | 做法 |
|---|---|---|---|
| M1 | **parent 版本** | 根 `pom.xml` | `3.5.10-SNAPSHOT` → `4.1.1`；移除 `spring-snapshots` 的 `<repositories>` 與 `<pluginRepositories>` |
| M2 | **自動配置類別搬家** | `Jacky917SecurityAutoConfiguration` | 見 [§4.1](#41-自動配置的執行順序)。Boot 4 把安全相關的自動配置搬到新模組與新套件，舊的 `import` 會編譯失敗 |
| M3 | **`@AutoConfigureMockMvc` 搬家** | 4 個整合測試 | `org.springframework.boot.test.autoconfigure.web.servlet` → `org.springframework.boot.webmvc.test.autoconfigure` |
| M4 | **Jackson 2 不再是預設** | `Jacky917SecurityAutoConfiguration`（錯誤回應）、`DemoJwtDecoderConfiguration`、`JwtIssuerService`、`GenerateTestJwtMain` | 見 [§4.2](#42-jackson-3) |
| M5 | **測試 starter 改為模組化** | 3 個模組的 `pom.xml` | `spring-boot-starter-test` + `spring-security-test` → `spring-boot-starter-security-test` + `spring-boot-starter-webmvc-test`（兩者都會帶入 `spring-boot-starter-test`） |
| M6 | **springdoc 版本** | 兩個 demo 的 `pom.xml` | `2.8.13` → `3.1.1` |

### 3.2 建議一起改（不改仍可運作，但會出現棄用警告或留下隱患）

| # | 變更 | 影響檔案 | 說明 |
|---|---|---|---|
| S1 | **Starter 改名** | 3 個模組的 `pom.xml` | 舊名稱在 4.1.1 仍存在，但描述已標示「deprecated」：`spring-boot-starter-web` → `spring-boot-starter-webmvc`；`spring-boot-starter-oauth2-resource-server` → `spring-boot-starter-security-oauth2-resource-server` |
| S2 | **路徑比對器改為 `PathPatternRequestMatcher`** | `permit-all-patterns` 的語意、文件 | Spring Security 7 已移除 `AntPathRequestMatcher` 與 `MvcRequestMatcher`（已確認 7.1.1 的 jar 中不存在）。`**` 只能出現在路徑的**開頭或結尾**，`/api/**/admin` 這類寫法會在啟動時失敗（已實測）。預設清單都是結尾 `**`，不受影響，但必須寫進文件與升級說明 |
| S3 | **外掛版本** | `demo-resource-server/pom.xml` | ~~改由 parent 管理~~ 實測發現 **Spring Boot 4 不再管理 `exec-maven-plugin` 的版本**，改為明確指定 `3.6.4` |
| S4 | **檢查 annotation processor 的版本屬性** | 根 `pom.xml` | 已確認：Boot 4.1.1 的 parent 仍提供 `${spring-boot.version}` 與 `${lombok.version}`，不需修改 |
| S5 | **CI 與發佈流程** | `.github/workflows/` | 加上 Java 21 與 25 的測試矩陣（見 [Repo 拆分設計](repo-structure-design.md#8-ci-與發佈)） |

### 3.3 已確認不受影響

以下 API 已確認在 Spring Security 7.1.1 中仍存在、套件不變，程式碼不需修改：

| 類別 | 用途 |
|---|---|
| `org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults` | `@Require*` 註解的 `{value}` 佔位符 |
| `org.springframework.security.access.prepost.PreAuthorize` | 方法級授權 |
| `org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter` | JWT 轉換 |
| `org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint` | 401 的 `WWW-Authenticate` 標頭 |

另外，Starter 原本就全面使用 Lambda DSL（`http.csrf(csrf -> ...)`），不受 Spring Security 7 移除 `and()` 等舊寫法的影響。

---

## 4. 設計細節

### 4.1 自動配置的執行順序

Boot 4.1.1 的類別位置（已確認）：

| 用途 | Boot 3.5 | Boot 4.1.1 |
|---|---|---|
| 安全性核心 | `o.s.boot.autoconfigure.security.servlet.SecurityAutoConfiguration` | `o.s.boot.security.autoconfigure.SecurityAutoConfiguration` |
| 預設 Servlet filter chain | （包含在上面） | `o.s.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration` |
| Resource Server | `o.s.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration` | `o.s.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration` |
| Resource Server 的 filter chain | （包含在上面） | `o.s.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration` |

（`o.s` = `org.springframework`）

**做法：改用字串形式的 `beforeName`**

```java
@AutoConfiguration(beforeName = {
        "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration"
})
```

| 寫法 | 類別不存在時 | 評估 |
|---|---|---|
| `before = {X.class}` | 編譯失敗或啟動時 `ClassNotFoundException` | 綁死單一 Boot 版本 |
| **`beforeName = {"..."}`** | 該項被忽略 | ✅ 不會因為 Boot 搬動類別而直接失敗 |

**必須新增的測試**：用 `beforeName` 時，類別名稱打錯不會有任何錯誤。整合測試確認：

1. **`beforeName` 列出的每個類別都存在**：名稱打錯或 Spring Boot 搬移類別時直接失敗。
2. 應用程式中只有 Starter 的 `SecurityFilterChain`（Boot 的預設 filter chain 沒有被建立）。
3. 應用程式中只有一個 `JwtAuthenticationConverter`，而且是 Starter 提供的（[限制 §5](../resource-server/limitations.md#5-spring-boot-原生的-jwt-converter-屬性無效)）。

> **實測補充（PR #2 review）**：Spring Boot 排序自動配置時，先依類別名稱的字母順序，再套用 `before`／`after`。`jacky917.…` 本來就排在 `org.springframework.…` 之前，因此即使把 `beforeName` 整個刪掉，第 2、3 項仍然會通過。第 2、3 項驗證的是「目前行為正確」，**只有第 1 項能抓到 `beforeName` 寫錯**。`beforeName` 是日後套件名稱改變時的保險。測試應用程式也改為只用 `@EnableAutoConfiguration`（不直接 `@Import`），與實際使用者的載入方式相同。

### 4.2 Jackson 3

Boot 4 預設使用 Jackson 3（groupId `tools.jackson`，類別 `tools.jackson.databind.json.JsonMapper`）。目前有 4 處使用 Jackson 2 的 `com.fasterxml.jackson.databind.ObjectMapper`。

**Starter：錯誤回應的 JSON**

| 選項 | 說明 | 評估 |
|---|---|---|
| A. 引入已棄用的 `spring-boot-jackson2` | 程式不用改 | 依賴一個已棄用的模組，下個大版本又要改 ❌ |
| **B. 注入應用程式的 Jackson 3 `JsonMapper`** | `ObjectProvider<JsonMapper>`，取不到時自行建立 | ✅ 順便修正 [限制 §12](../resource-server/limitations.md#12-錯誤回應的限制)：`spring.jackson.*` 設定將會生效 |
| C. 手寫 JSON | 只有 5 個欄位 | 完全不依賴 Jackson，但 `message`、`path` 需要自行跳脫特殊字元，容易出錯 |

**推薦 B**。`spring-boot-starter-webmvc` 已經帶入 Jackson 3，不需要新增依賴。

**Demo：讀取 JWK 檔**

`DemoJwtDecoderConfiguration` 與 `JwtIssuerService` 先用 Jackson 讀檔，再轉回字串交給 Nimbus。改為直接讀取字串並呼叫 `OctetSequenceKey.parse(String)`，**完全移除 Jackson 的使用**。

**Demo：`GenerateTestJwtMain`**

依先前的整理建議刪除（與 `JwtIssuerService` 重複）。若保留，比照上面的方式修改。

### 4.3 路徑比對規則的變化

`permit-all-patterns` 由 `requestMatchers(String...)` 處理，在 Spring Security 7 中改用 `PathPatternRequestMatcher`：

| 寫法 | Boot 3.5 | Boot 4.1 |
|---|---|---|
| `/public/**` | ✅ | ✅ |
| `/api/*/health` | ✅ | ✅ |
| `/api/**/admin`（`**` 在中間） | ✅ | ❌ **啟動失敗** |
| `/files/*.png` | ✅ | ✅ |

這是給使用者的**破壞性變更**，要寫進升級說明，並更新 [設定參考](../resource-server/configuration.md) 的 `permit-all-patterns` 說明。

---

## 5. 版本與分支策略

詳見 [Repo 拆分設計 §7](repo-structure-design.md#7-版本與分支策略)，摘要如下：

```
main ─── (目前 1.0.0) ──┬── 升級 Boot 4.1 ── 2.0.0-M1 ── … ── 2.0.0
                        │
                        └── 1.x 分支：parent 改為 3.5.16 正式版 ── 1.1.0 ── 只修安全問題
```

| 版本線 | Spring Boot | 維護方式 |
|---|---|---|
| `1.x` | 3.5.16（最終版） | 只修安全問題與嚴重 bug，至 2.0.0 正式發佈後 6 個月 |
| `2.x` | 4.1.x | 主要開發線 |

---

## 6. 實施步驟

每一步都要能獨立通過 `mvn clean verify`，方便定位問題。

| 步驟 | 內容 | 驗證 |
|---|---|---|
| 0 | **先 commit 目前所有未提交的變更**，建立 `1.x` 分支；在 `1.x` 將 parent 改為 `3.5.16`，發佈 `1.1.0` | `1.x` 上 37 個測試通過 |
| 1 | `main`：版本改為 `2.0.0-SNAPSHOT`；parent 改為 `4.1.1`；移除 SNAPSHOT repository（M1） | 預期會編譯失敗，確認錯誤清單與 §3 相符 |
| 2 | Starter 改名、測試 starter 改為模組化（S1、M5） | 依賴解析成功 |
| 3 | 自動配置改用 `beforeName`，新增 §4.1 的排序測試（M2） | 自動配置模組編譯通過 |
| 4 | 錯誤回應改用 Jackson 3 `JsonMapper`（M4） | `SecurityBehaviorIntegrationTest` 通過 |
| 5 | 測試的 `@AutoConfigureMockMvc` 改套件（M3） | autoconfigure 模組全部測試通過 |
| 6 | Demo：移除 Jackson 2、springdoc 升級、外掛版本（M4、M6、S3） | 全部測試通過 |
| 7 | 手動 E2E：依 [E2E 測試指南](../guides/e2e-testing.md) 啟動兩個 demo 走一遍 | 所有端點結果與 Boot 3.5 一致 |
| 8 | 更新文件：相容性表格、starter 名稱、`permit-all-patterns` 規則、限制文件 | 文件連結檢查通過 |
| 9 | 發佈 `2.0.0-M1` | 另建一個空專案，引入 `2.0.0-M1` 確認可以正常使用 |

### 行為回歸檢查

升級後**行為必須完全相同**的項目（皆已有測試）：

| 行為 | 測試 |
|---|---|
| 401／403 JSON 格式與 `WWW-Authenticate` | `SecurityBehaviorIntegrationTest` |
| 放行路徑、放行路徑上的無效 Token | 同上 |
| 註解疊加時拋出例外 | 同上（Spring Security 7 若改變此行為，要同步更新 [限制 §1](../resource-server/limitations.md#1-同一個方法只能有一個授權註解)） |
| 類別與方法註解不合併 | 同上 |
| 五種 `@Require*` 註解 | `MethodSecurityAnnotationsIntegrationTest` |
| claims → authorities | `JwtAuthoritiesExtractorTest` |
| AND／OR 判斷與 fail-closed | `Jacky917AuthorityEvaluatorTest` |
| Demo 全流程 | `DemoResourceServerIntegrationTest`、`AuthControllerIntegrationTest` |

---

## 7. 風險

| 風險 | 可能性 | 影響 | 對策 |
|---|---|---|---|
| `beforeName` 類別名稱打錯，排序靜默失效 | 中 | 高（Boot 的預設 filter chain 取代 Starter 的） | §4.1 的排序測試 |
| Spring Security 7 的方法級授權行為有細微變化 | 低 | 中 | 現有的行為測試會發現；若有改變，同步更新限制文件 |
| 使用者的 `permit-all-patterns` 中有 `**` 在中間的寫法 | 低 | 中（升級後啟動失敗） | 升級說明中列為破壞性變更 |
| 使用者自己的專案還在 Boot 3 | 高 | 低 | `1.x` 分支持續提供安全修補一段時間 |
| demo 的 Hibernate 7 行為差異 | 低 | 低 | demo 的實體很簡單；整合測試會發現 |

---

## 8. 使用者的升級說明（草稿）

發佈 `2.0.0` 時附上：

1. 需要 Spring Boot 4.1 以上、Java 21 以上。
2. 依賴改名（見 [Repo 拆分設計 §5](repo-structure-design.md#5-命名規則)）。
3. `permit-all-patterns` 中，`**` 只能放在路徑的開頭或結尾。
4. 錯誤回應 JSON 改由應用程式的 Jackson 設定序列化，`spring.jackson.*` 將會生效。
5. 測試請改用 `spring-boot-starter-security-test` 與 `spring-boot-starter-webmvc-test`。
6. 2.0 一併納入的其他破壞性變更，見 [2.0 總設計 §4](v2-overview.md#4-20-的破壞性變更清單)。

---

## 9. 實施結果

| 項目 | 結果 |
|---|---|
| 分支 | `claude/spring-boot-4.1-upgrade`（自 PR #1 的分支切出） |
| 版本 | `2.0.0-SNAPSHOT`，parent `spring-boot-starter-parent:4.1.1` |
| 建置 | `mvn clean verify`：**41 個測試全數通過**（原 37 個 + 新增 4 個） |
| 手動 E2E | 兩個 demo 以 Boot 4.1.1 啟動，依 [E2E 測試指南](../guides/e2e-testing.md) 的 14 個請求結果全部符合預期。因本機 Docker 未啟動，Resource Server 改以 H2 執行（未驗證 MySQL Connector/J 9.7.0） |

### 新增的測試

| 測試 | 驗證內容 |
|---|---|
| `AutoConfigurationOrderingIntegrationTest` | `beforeName` 列出的類別都存在；只有 Starter 的 `SecurityFilterChain` 與 `JwtAuthenticationConverter`，即使設定 `principal-claim-name`、`authority-prefix` 也不會使用 Spring Boot 的 converter（見 §4.1 的實測補充） |
| `ErrorResponseJsonMapperIntegrationTest` | 錯誤回應使用應用程式的 Jackson 3 `JsonMapper`（`spring.jackson.serialization.indent-output` 生效） |
| `SecurityBehaviorIntegrationTest#protectedResourceMetadataIsPublic` | RFC 9728 metadata 端點可匿名存取 |

### 升級時才發現的行為差異（設計階段未預期）

| 差異 | 說明 | 處理 |
|---|---|---|
| **`FACTOR_BEARER` authority** | Spring Security 7 的 `JwtAuthenticationConverter` 會在 `Authentication` 中額外加入 `FACTOR_BEARER`，代表以 Bearer Token 驗證（多因素驗證功能的一部分）。`/secure/me` 等列出 authority 的地方會多出這一項 | 不影響 `@Require*` 等「是否包含」的判斷；文件中說明不要比對整個 authority 清單 |
| **`WWW-Authenticate` 多了 `resource_metadata`** | 依 RFC 9728，401 回應的標頭變成 `Bearer resource_metadata="…/.well-known/oauth-protected-resource"`，並自動提供該端點（匿名可存取） | 測試改為檢查以 `Bearer` 開頭；文件更新 |
| **`exec-maven-plugin` 不再由 Boot 管理** | 移除寫死的版本後出現 Maven 警告 | 明確指定 `3.6.4` |
| **`**` 在開頭也可以** | 錯誤訊息為「should be placed at the start or end of the pattern」 | 文件改為「只能放在開頭或結尾」 |

### 與設計一致、行為不變的部分

- 註解疊加仍然在呼叫時拋出 `AnnotationConfigurationException`（[限制 §1](../resource-server/limitations.md#1-同一個方法只能有一個授權註解) 不變）。
- 類別與方法的註解仍然不合併（[限制 §2](../resource-server/limitations.md#2-類別與方法的註解不會合併) 不變）。
- 放行路徑帶無效 Token 仍回 401；401／403 JSON 格式不變。

### 尚未完成

- MySQL 環境的實際驗證（需要 Docker）。
- 發佈 `2.0.0-M1`（依計畫在合併後進行）。

