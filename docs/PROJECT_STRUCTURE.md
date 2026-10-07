# 專案結構 (PROJECT STRUCTURE)

本文件使用 `tree -a -I 'target|.git|.idea|.cursor'` 的輸出來展示目前專案真實結構（`.idea`、`.cursor` 為本機 IDE／工具設定，未納入版本控制，故排除）。  
**每次執行後都必須更新，以反映最新狀態。**

---
## 當前目錄樹

```
.
|-- .github
|   `-- workflows
|       `-- publish.yml
|-- .gitignore
|-- README.md
|-- demo-authorization-server
|   |-- pom.xml
|   `-- src
|       |-- main
|       |   |-- java
|       |   |   `-- jacky917
|       |   |       `-- demo
|       |   |           `-- authorizationserver
|       |   |               |-- DemoAuthorizationServerApplication.java
|       |   |               |-- controller
|       |   |               |   |-- AuthController.java
|       |   |               |   |-- TokenRequest.java
|       |   |               |   `-- TokenResponse.java
|       |   |               `-- service
|       |   |                   `-- JwtIssuerService.java
|       |   `-- resources
|       |       |-- application.yml
|       |       `-- demo
|       |           `-- jwk
|       |               `-- demo-hs256.jwk.json
|       `-- test
|           `-- java
|               `-- jacky917
|                   `-- demo
|                       `-- authorizationserver
|                           `-- AuthControllerIntegrationTest.java
|-- demo-resource-server
|   |-- pom.xml
|   `-- src
|       |-- main
|       |   |-- java
|       |   |   `-- jacky917
|       |   |       `-- demo
|       |   |           `-- resourceserver
|       |   |               |-- DemoResourceServerApplication.java
|       |   |               |-- authz
|       |   |               |   |-- AuthzService.java
|       |   |               |   |-- DemoAuthzConfiguration.java
|       |   |               |   `-- DenyAllAuthzService.java
|       |   |               |-- clip
|       |   |               |   |-- Clip.java
|       |   |               |   |-- ClipDemoDataInitializer.java
|       |   |               |   `-- ClipRepository.java
|       |   |               |-- config
|       |   |               |   |-- DemoJwtDecoderConfiguration.java
|       |   |               |   `-- DemoSwaggerConfiguration.java
|       |   |               |-- controller
|       |   |               |   `-- DemoSecureController.java
|       |   |               `-- tools
|       |   |                   `-- GenerateTestJwtMain.java
|       |   `-- resources
|       |       |-- application.yml
|       |       `-- demo
|       |           `-- jwk
|       |               `-- demo-hs256.jwk.json
|       `-- test
|           |-- java
|           |   `-- jacky917
|           |       `-- demo
|           |           `-- resourceserver
|           |               `-- DemoResourceServerIntegrationTest.java
|           `-- resources
|               `-- application.yml
|-- docs
|   |-- PROGRESS.md
|   |-- PROJECT_STRUCTURE.md
|   |-- auth-server-data-model.md
|   |-- auth-server-design.md
|   |-- auth-server-detailed-design.md
|   |-- authorization-model.md
|   |-- boot4-migration-design.md
|   |-- configuration.md
|   |-- database-schema.md
|   |-- e2e-testing.md
|   |-- getting-started.md
|   |-- github-packages.md
|   |-- jwt-claims.md
|   |-- limitations.md
|   |-- refresh-rotation.md
|   |-- repo-structure-design.md
|   |-- starter-design.md
|   |-- troubleshooting.md
|   `-- v2-overview.md
|-- jacky917-security-annotations
|   |-- pom.xml
|   `-- src
|       `-- main
|           `-- java
|               `-- jacky917
|                   `-- security
|                       `-- annotations
|                           |-- RequireAll.java
|                           |-- RequireAny.java
|                           |-- RequirePerm.java
|                           |-- RequireRole.java
|                           `-- RequireScope.java
|-- jacky917-security-autoconfigure
|   |-- pom.xml
|   `-- src
|       |-- main
|       |   |-- java
|       |   |   `-- jacky917
|       |   |       `-- security
|       |   |           `-- autoconfigure
|       |   |               |-- authentication
|       |   |               |   `-- JwtAuthoritiesExtractor.java
|       |   |               |-- config
|       |   |               |   `-- Jacky917SecurityAutoConfiguration.java
|       |   |               |-- methodsecurity
|       |   |               |   `-- Jacky917AuthorityEvaluator.java
|       |   |               `-- properties
|       |   |                   `-- Jacky917SecurityProperties.java
|       |   `-- resources
|       |       `-- META-INF
|       |           `-- spring
|       |               `-- org.springframework.boot.autoconfigure.AutoConfiguration.imports
|       `-- test
|           `-- java
|               `-- jacky917
|                   `-- security
|                       `-- autoconfigure
|                           |-- authentication
|                           |   `-- JwtAuthoritiesExtractorTest.java
|                           |-- integration
|                           |   |-- AutoConfigurationOrderingIntegrationTest.java
|                           |   |-- ErrorResponseJsonMapperIntegrationTest.java
|                           |   |-- MethodSecurityAnnotationsIntegrationTest.java
|                           |   `-- SecurityBehaviorIntegrationTest.java
|                           `-- methodsecurity
|                               `-- Jacky917AuthorityEvaluatorTest.java
|-- jacky917-security-starter
|   |-- pom.xml
|   `-- src
|       `-- main
|           `-- java
|               `-- jacky917
|                   `-- security
|                       `-- starter
`-- pom.xml

78 directories, 59 files
```

---
## 檔案用途說明

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `pom.xml` | `parent` | 根 POM (Parent) | 繼承 `spring-boot-starter-parent:4.1.1`；定義所有子模組、共享依賴版本與建置策略；宣告 Lombok 與 configuration-processor 的 `annotationProcessorPaths`（JDK 23+ 必要）。 |
| `.github/workflows/publish.yml` | `ci` | 發佈流程 | Release 發佈時將 parent 與三個 starter 模組部署到 GitHub Packages。 |
| `jacky917-security-starter/pom.xml` | `starter` | 聚合依賴模組 | 對外提供單一 starter 依賴入口，無程式碼。 |
| `jacky917-security-annotations/` | `annotations` | 自訂授權註解模組 | 提供 `@RequireRole/@RequirePerm/@RequireAny/@RequireAll/@RequireScope`，底層皆為 `@PreAuthorize` 樣板。 |
| `.../config/Jacky917SecurityAutoConfiguration.java` | `autoconfigure` | 自動配置入口 | 建立 filter chain、JWT converter、evaluator、401/403 JSON；在 Boot 原生安全配置之前執行。 |
| `.../authentication/JwtAuthoritiesExtractor.java` | `autoconfigure` | claims → authorities | 讀取 `roles/permissions/scope/scp`，加前綴、去重、排序。 |
| `.../methodsecurity/Jacky917AuthorityEvaluator.java` | `autoconfigure` | AND / OR 判斷 | 供 `@RequireAny/@RequireAll` 呼叫；參數無效時一律拒絕。 |
| `.../properties/Jacky917SecurityProperties.java` | `autoconfigure` | Starter 屬性 | `jacky917.security.*`；含預設 `permitAllPatterns`（含 Swagger/OpenAPI）。 |
| `.../META-INF/spring/...AutoConfiguration.imports` | `autoconfigure` | 自動配置註冊 | 讓 Spring Boot 載入 `Jacky917SecurityAutoConfiguration`。 |
| `.../JwtAuthoritiesExtractorTest.java` | `autoconfigure-test` | 單元測試 | claims 型態、去重、排序、prefix 覆寫與 `null` 前綴。 |
| `.../Jacky917AuthorityEvaluatorTest.java` | `autoconfigure-test` | 單元測試 | AND/OR 判斷與「空參數不可放行」回歸測試。 |
| `.../MethodSecurityAnnotationsIntegrationTest.java` | `autoconfigure-test` | 整合測試 | 四種自訂註解的 200/403。 |
| `.../AutoConfigurationOrderingIntegrationTest.java` | `autoconfigure-test` | 整合測試 | 確認 `beforeName` 排序生效：只有 Starter 的 filter chain 與 JWT converter。 |
| `.../ErrorResponseJsonMapperIntegrationTest.java` | `autoconfigure-test` | 整合測試 | 錯誤回應使用應用程式的 Jackson 3 `JsonMapper`。 |
| `.../SecurityBehaviorIntegrationTest.java` | `autoconfigure-test` | 整合測試 | 驗證 `docs/limitations.md` 描述的行為：401/403 JSON、`WWW-Authenticate`、放行路徑、註解覆蓋與疊加限制。 |
| `demo-resource-server/pom.xml` | `demo-resource` | Resource Demo 建置設定 | 含 Web、JPA、MySQL、H2（測試）、Swagger；不發佈。 |
| `.../DemoResourceServerApplication.java` | `demo-resource` | Resource Demo 啟動入口 | port 8080。 |
| `.../controller/DemoSecureController.java` | `demo-resource` | 安全端點控制器 | permitAll、authenticated、RBAC、AND/OR、ABAC 範例。 |
| `.../authz/AuthzService.java` | `demo-resource` | ABAC 介面 | `canAccessClip(authentication, clipId)`。 |
| `.../authz/DenyAllAuthzService.java` | `demo-resource` | ABAC 預設實作 | 一律拒絕。 |
| `.../authz/DemoAuthzConfiguration.java` | `demo-resource` | ABAC 規則配置 | 以 `clip.ownerId == JWT sub` 判斷，找不到資料時拒絕。 |
| `.../clip/Clip.java` | `demo-resource` | ABAC 示範實體 | `id/name/ownerId`。 |
| `.../clip/ClipRepository.java` | `demo-resource` | ABAC 示範 Repository | 供 ABAC 規則查詢 owner。 |
| `.../clip/ClipDemoDataInitializer.java` | `demo-resource` | Demo 初始化資料 | 啟動時建立 `demo-001`（alice）、`private-001`（bob）。 |
| `.../config/DemoJwtDecoderConfiguration.java` | `demo-resource` | JwtDecoder 範例 | 從 JWK 檔載入 HS256 金鑰，驗證簽章與 issuer。 |
| `.../config/DemoSwaggerConfiguration.java` | `demo-resource` | OpenAPI 設定 | 加入 bearer JWT 安全方案。 |
| `.../tools/GenerateTestJwtMain.java` | `demo-resource` | 測試 JWT CLI | 以 demo 金鑰產生 Token。 |
| `demo-resource-server/src/main/resources/application.yml` | `demo-resource` | 執行設定 | MySQL `localhost:3307/demo_db`（root/root）、`ddl-auto=update`、放行路徑。 |
| `demo-resource-server/src/test/resources/application.yml` | `demo-resource-test` | 測試設定 | 使用 H2（MySQL mode）避免測試依賴外部 DB。 |
| `.../DemoResourceServerIntegrationTest.java` | `demo-resource-test` | 整合測試 | 401/403/200、AND/OR 與資料庫導向 ABAC。 |
| `*/src/main/resources/demo/jwk/demo-hs256.jwk.json` | `demo-*` | 測試金鑰 | 兩個 demo 共用的 HS256 JWK，僅供本地測試。 |
| `demo-authorization-server/pom.xml` | `demo-auth` | Auth Demo 建置設定 | 含 Web、JOSE、Swagger；不發佈。 |
| `.../controller/AuthController.java` | `demo-auth` | Token 發行 API | `POST /oauth2/token`，固定密碼 `password`，僅供本地測試。 |
| `.../controller/TokenRequest.java`、`TokenResponse.java` | `demo-auth` | 請求／回應 DTO | |
| `.../service/JwtIssuerService.java` | `demo-auth` | JWT 簽發服務 | HS256，`iss=jacky917-demo-auth-server`、`aud=demo-resource-server`。 |
| `.../AuthControllerIntegrationTest.java` | `demo-auth-test` | 整合測試 | 驗證簽發成功與錯誤密碼 401。 |
| `README.md` | `project` | 專案入口 | 功能概覽、快速開始、預設行為、文件導覽、Demo 操作。 |
| `docs/getting-started.md` | `docs` | 使用指南 | 引入依賴、JwtDecoder、放行路徑、註解、ABAC、錯誤回應、覆寫、測試、上線清單。 |
| `docs/configuration.md` | `docs` | 設定參考 | 所有屬性、預設值、與 Spring Boot 原生屬性的關係。 |
| `docs/limitations.md` | `docs` | 限制與注意事項 | 已知限制、風險與解法（部分有測試驗證）。 |
| `docs/troubleshooting.md` | `docs` | 疑難排解 | 依症狀（啟動失敗、401、403、500、依賴解析）排查。 |
| `docs/starter-design.md` | `docs` | 設計與架構 | 請求流程、自動配置條件與順序、Bean 清單、擴充點。 |
| `docs/authorization-model.md` | `docs` | 授權模型 | RBAC / Permission / Scope / ABAC 的選擇與寫法。 |
| `docs/jwt-claims.md` | `docs` | JWT Claims 契約 | Token 格式、解析規則與範例。 |
| `docs/e2e-testing.md` | `docs` | E2E 操作手冊 | 雙服務啟動、取 token 與受保護端點驗證流程。 |
| `docs/github-packages.md` | `docs` | 發佈指南 | GitHub Packages 發佈與引用。 |
| `docs/v2-overview.md` | `docs` | 2.0 總設計 | 兩大任務（Boot 4.1 升級、Authorization Server）的目標、里程碑 M0～M6、破壞性變更與決策索引。 |
| `docs/boot4-migration-design.md` | `docs` | Boot 4.1 升級設計 | 版本對照、逐檔影響清單（已對照 Maven Central 查證）、步驟與風險。 |
| `docs/repo-structure-design.md` | `docs` | Repo 拆分設計 | 單一 repo 多模組、命名、flatten／BOM、版本與分支、CI、重構步驟。 |
| `docs/auth-server-data-model.md` | `docs` | AS 資料模型 | 23 張表的 DDL（含官方表 PostgreSQL 版）、欄位說明、索引、狀態機、關鍵查詢、seed、Flyway、DB 帳號、清理與容量估算；表設計的唯一權威來源。 |
| `docs/auth-server-detailed-design.md` | `docs` | AS 詳細設計 | D15～D21、元件與 SPI、filter chain、Token claim、流程（登入、第三方、刷新與重用偵測、登出、金鑰輪換）、設定規格、威脅模型、測試案例、工作分解。 |
| `docs/auth-server-design.md` | `docs` | Auth Server 設計（方案 C） | Spring Authorization Server、第三方登入、14 項決策、完整 DDL、流程與分階段計畫；狀態為設計草案。 |
| `docs/refresh-rotation.md`、`docs/database-schema.md` | `docs` | Auth Server 早期參考設計 | 已由 `auth-server-design.md` 取代主要內容，保留作為背景說明。 |
| `docs/PROGRESS.md` | `docs` | 進度追蹤 | 記錄每一步狀態、命令、決策與下一步。 |
| `docs/PROJECT_STRUCTURE.md` | `docs` | 專案結構 | 維護真實目錄樹與檔案用途表。 |
