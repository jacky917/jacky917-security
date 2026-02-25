# 專案結構 (PROJECT STRUCTURE)

本文件使用 `tree -a -I 'target|.git'` 的輸出來展示目前專案真實結構。  
**每次執行後都必須更新，以反映最新狀態。**

---
## 當前目錄樹

```
.
|-- .cursor
|   `-- rules
|       `-- jacky917-security.mdc
|-- .idea
|   |-- .gitignore
|   |-- compiler.xml
|   |-- encodings.xml
|   |-- jarRepositories.xml
|   |-- misc.xml
|   `-- workspace.xml
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
|       |   |               |   `-- DemoJwtDecoderConfiguration.java
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
|   |-- authorization-model.md
|   |-- database-schema.md
|   |-- e2e-testing.md
|   |-- github-packages.md
|   |-- jwt-claims.md
|   |-- refresh-rotation.md
|   `-- starter-design.md
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
|                           `-- integration
|                               `-- MethodSecurityAnnotationsIntegrationTest.java
|-- jacky917-security-starter
|   |-- pom.xml
|   `-- src
|       `-- main
|           `-- java
|               `-- jacky917
|                   `-- security
|                       `-- starter
|-- pom.xml
`-- test.txt
```

---
## 檔案用途說明

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `pom.xml` | `parent` | 根 POM (Parent) | 定義所有子模組、共享依賴版本與建置策略。 |
| `jacky917-security-starter/` | `starter` | 聚合依賴模組 | 對外提供單一 starter 依賴入口。 |
| `jacky917-security-autoconfigure/` | `autoconfigure` | 安全自動配置核心 | 提供 JWT 驗證、權限映射與 401/403 JSON 錯誤回應。 |
| `jacky917-security-annotations/` | `annotations` | 自訂授權註解模組 | 提供 `@RequireRole/@RequirePerm/@RequireAny/@RequireAll/@RequireScope`。 |
| `.../Jacky917SecurityProperties.java` | `autoconfigure` | Starter 屬性 | 含預設 `permitAllPatterns`（含 Swagger/OpenAPI）。 |
| `demo-resource-server/pom.xml` | `demo-resource` | Resource Demo 建置設定 | 含 Web、JPA、MySQL、Swagger、測試依賴。 |
| `.../DemoResourceServerApplication.java` | `demo-resource` | Resource Demo 啟動入口 | 啟動受保護 API 服務。 |
| `.../controller/DemoSecureController.java` | `demo-resource` | 安全端點控制器 | 提供 permitAll、authenticated、RBAC、AND/OR、ABAC，並加上 OpenAPI 註解。 |
| `.../clip/Clip.java` | `demo-resource` | ABAC 示範實體 | 定義 `id/name/ownerId`，模擬業務資料資源。 |
| `.../clip/ClipDemoDataInitializer.java` | `demo-resource` | Demo 初始化資料 | 啟動時補最小 Clip 測試資料，便於 Swagger/curl 直接驗證 ABAC。 |
| `.../clip/ClipRepository.java` | `demo-resource` | ABAC 示範 Repository | 提供 `Clip` 資料查詢，供 ABAC 規則判斷 owner。 |
| `.../authz/DemoAuthzConfiguration.java` | `demo-resource` | ABAC 規則配置 | 以 `clip.ownerId == JWT sub` 進行資料庫導向授權判斷。 |
| `demo-resource-server/src/main/resources/application.yml` | `demo-resource` | 執行設定 | 預設 MySQL 連線與 `spring.jpa.hibernate.ddl-auto=update`。 |
| `demo-resource-server/src/test/resources/application.yml` | `demo-resource-test` | 測試設定 | 使用 H2（MySQL mode）避免測試依賴外部 DB。 |
| `.../DemoResourceServerIntegrationTest.java` | `demo-resource-test` | 整合測試 | 覆蓋 401/403/200、AND/OR 與資料庫導向 ABAC。 |
| `demo-authorization-server/pom.xml` | `demo-auth` | Auth Demo 建置設定 | 含 Web、JOSE、Swagger。 |
| `.../controller/AuthController.java` | `demo-auth` | Token 發行 API | 提供 `POST /oauth2/token` 並加入 OpenAPI 註解。 |
| `.../AuthControllerIntegrationTest.java` | `demo-auth-test` | Auth Demo 整合測試 | 驗證簽發成功與錯誤密碼 401。 |
| `docs/PROGRESS.md` | `docs` | 進度追蹤 | 記錄每一步狀態、命令、決策與下一步。 |
| `docs/PROJECT_STRUCTURE.md` | `docs` | 專案結構 | 維護真實目錄樹與檔案用途表。 |
| `docs/e2e-testing.md` | `docs` | E2E 操作手冊 | 提供雙服務啟動、取 token 與受保護端點驗證流程。 |
| `README.md` | `project` | 使用與快速開始 | 提供 MySQL 準備、Swagger 入口與 Demo 操作說明。 |
