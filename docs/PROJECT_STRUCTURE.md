# 專案結構 (PROJECT STRUCTURE)

本文件使用 `tree -a -I 'target|.git|.idea|.cursor|.flattened-pom.xml'` 的輸出來展示目前專案真實結構（`.idea`、`.cursor` 為本機 IDE／工具設定，未納入版本控制；`.flattened-pom.xml` 為建置產物）。
**每次執行後都必須更新，以反映最新狀態。**

---
## 當前目錄樹

```
.
|-- .github
|   `-- workflows
|       |-- ci.yml
|       `-- publish.yml
|-- .gitignore
|-- README.md
|-- authorization-server
|   |-- jacky917-security-authorization-server-autoconfigure
|   |   |-- pom.xml
|   |   `-- src
|   |       |-- main
|   |       |   |-- java
|   |       |   |   `-- jacky917
|   |       |   |       `-- security
|   |       |   |           `-- authorizationserver
|   |       |   |               |-- autoconfigure
|   |       |   |               |   |-- AuthorizationServerAutoConfiguration.java
|   |       |   |               |   `-- AuthorizationServerDatabaseConfiguration.java
|   |       |   |               |-- database
|   |       |   |               |   |-- AuthorizationServerDialect.java
|   |       |   |               |   |-- AuthorizationServerDialects.java
|   |       |   |               |   |-- DefaultSqliteEnvironmentPostProcessor.java
|   |       |   |               |   |-- PostgresqlDialect.java
|   |       |   |               |   |-- SqliteDialect.java
|   |       |   |               |   |-- SqliteExceptionTranslator.java
|   |       |   |               |   `-- SqliteExceptionTranslatorPostProcessor.java
|   |       |   |               `-- properties
|   |       |   |                   `-- AuthorizationServerProperties.java
|   |       |   `-- resources
|   |       |       |-- META-INF
|   |       |       |   |-- spring
|   |       |       |   |   `-- org.springframework.boot.autoconfigure.AutoConfiguration.imports
|   |       |       |   `-- spring.factories
|   |       |       `-- db
|   |       |           `-- migration
|   |       |               `-- jacky917-as
|   |       |                   |-- postgresql
|   |       |                   |   |-- V1_0_0__identity.sql
|   |       |                   |   |-- V1_0_1__authorization_model.sql
|   |       |                   |   |-- V1_0_2__oauth2_official.sql
|   |       |                   |   |-- V1_0_3__oauth2_extensions.sql
|   |       |                   |   |-- V1_0_4__sessions.sql
|   |       |                   |   |-- V1_0_5__security.sql
|   |       |                   |   `-- V1_0_6__seed.sql
|   |       |                   `-- sqlite
|   |       |                       |-- V1_0_0__identity.sql
|   |       |                       |-- V1_0_1__authorization_model.sql
|   |       |                       |-- V1_0_2__oauth2_official.sql
|   |       |                       |-- V1_0_3__oauth2_extensions.sql
|   |       |                       |-- V1_0_4__sessions.sql
|   |       |                       |-- V1_0_5__security.sql
|   |       |                       `-- V1_0_6__seed.sql
|   |       `-- test
|   |           `-- java
|   |               `-- jacky917
|   |                   `-- security
|   |                       `-- authorizationserver
|   |                           |-- database
|   |                           |   |-- DatabaseMigrationIntegrationTest.java
|   |                           |   |-- DefaultSqliteIntegrationTest.java
|   |                           |   |-- SchemaConsistencyIntegrationTest.java
|   |                           |   |-- SchemaIntrospection.java
|   |                           |   `-- SqliteValidationIntegrationTest.java
|   |                           |-- properties
|   |                           |   `-- AuthorizationServerPropertiesTest.java
|   |                           `-- support
|   |                               `-- TestDatabases.java
|   `-- jacky917-security-authorization-server-starter
|       `-- pom.xml
|-- core
|   `-- jacky917-security-core
|       |-- pom.xml
|       `-- src
|           `-- main
|               `-- java
|                   `-- jacky917
|                       `-- security
|                           `-- core
|                               |-- Jacky917AuthorityPrefix.java
|                               |-- Jacky917ClaimNames.java
|                               `-- TrustLevel.java
|-- docs
|   |-- PROGRESS.md
|   |-- PROJECT_STRUCTURE.md
|   |-- design
|   |   |-- auth-server-data-model.md
|   |   |-- auth-server-design.md
|   |   |-- auth-server-detailed-design.md
|   |   |-- boot4-migration-design.md
|   |   |-- database-schema.md
|   |   |-- refresh-rotation.md
|   |   |-- repo-structure-design.md
|   |   |-- starter-design.md
|   |   `-- v2-overview.md
|   |-- guides
|   |   |-- e2e-testing.md
|   |   |-- github-packages.md
|   |   `-- upgrade-to-2.0.md
|   `-- resource-server
|       |-- authorization-model.md
|       |-- configuration.md
|       |-- getting-started.md
|       |-- jwt-claims.md
|       |-- limitations.md
|       `-- troubleshooting.md
|-- examples
|   |-- example-authorization-server
|   |   |-- pom.xml
|   |   `-- src
|   |       |-- main
|   |       |   |-- java
|   |       |   |   `-- jacky917
|   |       |   |       `-- demo
|   |       |   |           `-- authorizationserver
|   |       |   |               |-- DemoAuthorizationServerApplication.java
|   |       |   |               |-- controller
|   |       |   |               |   |-- AuthController.java
|   |       |   |               |   |-- TokenRequest.java
|   |       |   |               |   `-- TokenResponse.java
|   |       |   |               `-- service
|   |       |   |                   `-- JwtIssuerService.java
|   |       |   `-- resources
|   |       |       |-- application.yml
|   |       |       `-- demo
|   |       |           `-- jwk
|   |       |               `-- demo-hs256.jwk.json
|   |       `-- test
|   |           `-- java
|   |               `-- jacky917
|   |                   `-- demo
|   |                       `-- authorizationserver
|   |                           `-- AuthControllerIntegrationTest.java
|   `-- example-resource-server
|       |-- pom.xml
|       `-- src
|           |-- main
|           |   |-- java
|           |   |   `-- jacky917
|           |   |       `-- demo
|           |   |           `-- resourceserver
|           |   |               |-- DemoResourceServerApplication.java
|           |   |               |-- authz
|           |   |               |   |-- AuthzService.java
|           |   |               |   |-- DemoAuthzConfiguration.java
|           |   |               |   `-- DenyAllAuthzService.java
|           |   |               |-- clip
|           |   |               |   |-- Clip.java
|           |   |               |   |-- ClipDemoDataInitializer.java
|           |   |               |   `-- ClipRepository.java
|           |   |               |-- config
|           |   |               |   |-- DemoJwtDecoderConfiguration.java
|           |   |               |   `-- DemoSwaggerConfiguration.java
|           |   |               |-- controller
|           |   |               |   `-- DemoSecureController.java
|           |   |               `-- tools
|           |   |                   `-- GenerateTestJwtMain.java
|           |   `-- resources
|           |       |-- application.yml
|           |       `-- demo
|           |           `-- jwk
|           |               `-- demo-hs256.jwk.json
|           `-- test
|               |-- java
|               |   `-- jacky917
|               |       `-- demo
|               |           `-- resourceserver
|               |               `-- DemoResourceServerIntegrationTest.java
|               `-- resources
|                   `-- application.yml
|-- jacky917-security-bom
|   `-- pom.xml
|-- pom.xml
|-- relocation
|   `-- jacky917-security-starter
|       `-- pom.xml
|-- resource-server
|   |-- jacky917-security-annotations
|   |   |-- pom.xml
|   |   `-- src
|   |       `-- main
|   |           `-- java
|   |               `-- jacky917
|   |                   `-- security
|   |                       `-- annotations
|   |                           |-- RequireAll.java
|   |                           |-- RequireAny.java
|   |                           |-- RequirePerm.java
|   |                           |-- RequireRole.java
|   |                           `-- RequireScope.java
|   |-- jacky917-security-resource-server-autoconfigure
|   |   |-- pom.xml
|   |   `-- src
|   |       |-- main
|   |       |   |-- java
|   |       |   |   `-- jacky917
|   |       |   |       `-- security
|   |       |   |           `-- resourceserver
|   |       |   |               `-- autoconfigure
|   |       |   |                   |-- authentication
|   |       |   |                   |   `-- JwtAuthoritiesExtractor.java
|   |       |   |                   |-- config
|   |       |   |                   |   |-- Jacky917AuthorityEvaluatorAutoConfiguration.java
|   |       |   |                   |   `-- Jacky917SecurityAutoConfiguration.java
|   |       |   |                   |-- methodsecurity
|   |       |   |                   |   `-- Jacky917AuthorityEvaluator.java
|   |       |   |                   `-- properties
|   |       |   |                       `-- Jacky917SecurityProperties.java
|   |       |   `-- resources
|   |       |       `-- META-INF
|   |       |           `-- spring
|   |       |               `-- org.springframework.boot.autoconfigure.AutoConfiguration.imports
|   |       `-- test
|   |           `-- java
|   |               `-- jacky917
|   |                   `-- security
|   |                       `-- resourceserver
|   |                           `-- autoconfigure
|   |                               |-- authentication
|   |                               |   `-- JwtAuthoritiesExtractorTest.java
|   |                               |-- integration
|   |                               |   |-- AutoConfigurationOrderingIntegrationTest.java
|   |                               |   |-- ErrorResponseJsonMapperIntegrationTest.java
|   |                               |   |-- MethodSecurityAnnotationsIntegrationTest.java
|   |                               |   |-- PrefixAndDefaultsIntegrationTest.java
|   |                               |   |-- SecurityBehaviorIntegrationTest.java
|   |                               |   `-- StarterDisabledIntegrationTest.java
|   |                               |-- methodsecurity
|   |                               |   `-- Jacky917AuthorityEvaluatorTest.java
|   |                               `-- properties
|   |                                   `-- Jacky917SecurityPropertiesTest.java
|   `-- jacky917-security-resource-server-starter
|       |-- pom.xml
|       `-- src
|           `-- main
|               `-- java
|                   `-- jacky917
|                       `-- security
|                           `-- starter
`-- scripts
    `-- check-doc-links.py

126 directories, 115 files
```

---
## 檔案用途說明

### 建置與 CI

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `pom.xml` | `parent` | 根 POM（aggregator + 建置設定） | 繼承 `spring-boot-starter-parent:4.1.1`；`${revision}` 統一版本；flatten 產生不含 parent 的發佈 POM；enforcer 依賴方向規則；Lombok 與 configuration-processor 的 annotation processor。 |
| `jacky917-security-bom/pom.xml` | `bom` | BOM | 列出所有發佈模組的版本；flatten 以 bom 模式發佈。 |
| `relocation/jacky917-security-starter/pom.xml` | `relocation` | 舊座標 relocation | `com.github.jacky917:jacky917-security-starter` → 新的 resource server starter；只在 2.0.x 發佈。 |
| `.github/workflows/ci.yml` | `ci` | 持續整合 | push 到 `main`／`1.x` 與所有 PR：Java 21、25 建置與測試；文件連結檢查。 |
| `.github/workflows/publish.yml` | `ci` | 發佈流程 | Release 時檢查 tag 等於 `revision`、已宣告授權條款；整個 reactor 測試通過後才部署到 GitHub Packages。 |
| `scripts/check-doc-links.py` | `tooling` | 文件檢查 | README 與 docs 的相對連結（含標題與 `<...>` 寫法）、錨點（重複標題依 GitHub 規則加 `-1`）、YAML 範例；有問題即非 0 結束。 |

### Authorization Server（🚧 第 1 階段開發中）

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `authorization-server/jacky917-security-authorization-server-starter/` | `as-starter` | 登入服務引入的 starter | 聚合 AS autoconfigure。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerAutoConfiguration.java` | `as-autoconfigure` | 自動配置入口 | `enabled=false` 時停用；在 DataSource 之後執行。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerDatabaseConfiguration.java` | `as-autoconfigure` | 資料庫配置（D22） | 選擇並驗證 dialect；SQLite 例外轉換。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../properties/AuthorizationServerProperties.java` | `as-autoconfigure` | 設定屬性 | `jacky917.security.authorization-server.*`；實作 `Validator`，設定錯誤時啟動失敗。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/AuthorizationServerDialect.java` | `as-autoconfigure` | 資料庫方言 SPI | `PostgresqlDialect`、`SqliteDialect`；`AuthorizationServerDialects` 依 URL 選擇。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/SqliteDialect.java` | `as-autoconfigure` | SQLite 方言 | 檢查必要連線參數、PRAGMA、Hikari 自動提交；缺少即啟動失敗。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/DefaultSqliteEnvironmentPostProcessor.java` | `as-autoconfigure` | 預設值 | Flyway 位置；未設定 datasource 時使用 SQLite（建立權限 600 的檔案）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/SqliteExceptionTranslator.java` | `as-autoconfigure` | SQLite 例外轉換 | 約束違反轉為 `DuplicateKeyException` 等；由 `SqliteExceptionTranslatorPostProcessor` 套用到 `JdbcTemplate`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerKeysConfiguration.java` | `as-autoconfigure` | 簽章金鑰配置 | 首次啟動產生金鑰；`JWKSource`（只有公鑰）與只用 `ACTIVE` 私鑰的 `JwtEncoder`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/SigningKeyService.java` | `as-autoconfigure` | 金鑰服務 | 產生 RS256／ES256 金鑰、快取 1 分鐘、啟動時確認可解密。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/KeyEncryptor.java` | `as-autoconfigure` | 私鑰加密 | AES-256-GCM，`kid` 為附加驗證資料。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/SigningKeyStore.java`、`JdbcSigningKeyStore.java` | `as-autoconfigure` | 金鑰儲存 SPI | 預設 `signing_key` 表，可換成 KMS。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/RotatingJwkSource.java` | `as-autoconfigure` | JWKS | 公開 `NEXT`、`ACTIVE`、`RETIRING` 的公鑰。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerClientsConfiguration.java` | `as-autoconfigure` | Client 配置 | `PasswordEncoder`（`{bcrypt}`）、`RegisteredClientRepository`、啟動時同步設定中的 client。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../client/ClientRegistrationSynchronizer.java` | `as-autoconfigure` | Client 同步 | 依 `clients.*` 建立或更新 client；強制 PKCE、輪換 Refresh Token；secret 以 BCrypt 雜湊。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../client/ActiveClientRegisteredClientRepository.java` | `as-autoconfigure` | 停權過濾 | `client_profile` 不是 `ACTIVE` 的 client 對 Spring Security 而言不存在。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../client/ClientProfileRepository.java`、`ClientProfile.java`、`ClientStatus.java` | `as-autoconfigure` | Client 資料 | `client_profile` 的讀寫；信任等級與狀態。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerUsersConfiguration.java` | `as-autoconfigure` | 使用者配置 | 密碼政策、`UserAccountService`、`UserDetailsService`、第一位管理員。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../user/UserAccountService.java`、`JdbcUserAccountService.java` | `as-autoconfigure` | 使用者 SPI | 查詢（帳號或已驗證的 Email）、建立、登入成功、角色與權限（資料模型 §11.1）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../user/Jacky917UserDetailsService.java` | `as-autoconfigure` | 帳號密碼登入 | username = 使用者 ID（D16）；所有失敗原因相同；登入時自動重新雜湊。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../user/PasswordPolicy.java`、`BootstrapAdminInitializer.java` | `as-autoconfigure` | 密碼政策、第一位管理員 | 12～128 字元；沒有 `AS_ADMIN` 時建立一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../support/UuidV7.java` | `as-autoconfigure` | ID 產生 | 依時間排序的 UUID（RFC 9562）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerSecurityConfiguration.java` | `as-autoconfigure` | Web 安全設定 | Order 1：SAS 端點（含 OIDC、`/userinfo`）；Order 3：登入頁、CSRF、更換 Session ID、CSP。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/AuthSessionService.java`、`AuthSession.java` | `as-autoconfigure` | 登入 Session | 建立與查詢 `auth_session`；瀏覽器 Session 屬性存放 `asid`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/SessionLinkingAuthorizationService.java` | `as-autoconfigure` | 授權連結 | 包裝官方 JDBC 授權服務：新授權在同一個交易中連結到同一位使用者的 `ACTIVE` 登入 Session。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/SessionAuthorizationRepository.java` | `as-autoconfigure` | 連結資料 | `session_authorization` 的查詢與建立（`ON CONFLICT DO NOTHING`）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../token/Jacky917TokenCustomizer.java` | `as-autoconfigure` | Token 的 claim | `aud`、`client_id`、`asid`、`idp`、`roles`、`permissions`、ID Token 的 `amr` 與使用者資料；簽發時檢查使用者與 Session 狀態。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../token/AuthorityResolver.java`、`DefaultAuthorityResolver.java` | `as-autoconfigure` | 權限計算 SPI | 第一方：全部角色與權限；第三方：scope 涵蓋的權限（資料模型 §11.3）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../token/AudienceResolver.java`、`ConfiguredAudienceResolver.java`、`TokenClaimsContributor.java` | `as-autoconfigure` | Token SPI | `aud`；業務自訂 claim。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedLoginSuccessHandler.java` | `as-autoconfigure` | 第三方登入成功 | 轉換使用者、找到或建立帳號、建立 `auth_session`（`FEDERATED`）、以標準 principal 取代、移除提供者的 token。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedIdentityService.java` | `as-autoconfigure` | 外部帳號 | 已連結 → 登入；已驗證的 Email 屬於既有帳號 → 拒絕；其餘建立新使用者。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedUserInfoMapper.java`、`OidcFederatedUserInfoMapper.java`、`FederatedUserInfo.java` | `as-autoconfigure` | 提供者資料轉換 SPI | 通用 OIDC（Google 等）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/PrincipalNormalizer.java` | `as-autoconfigure` | D16 | 轉為 `UsernamePasswordAuthenticationToken` + `User(使用者 ID)`；補上 factor authority。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/LoginSuccessHandler.java` | `as-autoconfigure` | 登入成功 | 記錄登入、建立 `auth_session`、回到授權請求。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/LoginController.java` | `as-autoconfigure` | 登入頁 | 依語言顯示；所有錯誤顯示相同訊息；`/jacky917/theme.css`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/main/resources/templates/jacky917/`、`static/jacky917/`、`jacky917/authorization-server-messages*.properties` | `as-autoconfigure` | 登入頁資源 | Thymeleaf 範本、樣式、英文與繁體中文訊息。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/main/resources/db/migration/jacky917-as/{postgresql,sqlite}/` | `as-autoconfigure` | Flyway V1 | 兩種資料庫各 7 個同名檔案：23 張表與內建資料。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../support/TestDatabases.java` | `as-test` | 測試資料庫 | SQLite 暫存檔；embedded PostgreSQL 16（不需 Docker）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../database/*IntegrationTest.java` | `as-test` | 整合測試 | migration、官方 JDBC 類別相容性、約束、schema 一致性、SQLite 設定檢查、預設 SQLite。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../properties/AuthorizationServerPropertiesTest.java` | `as-test` | 單元測試 | 預設值、issuer、有效期與主金鑰驗證。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../keys/KeyEncryptorTest.java` | `as-test` | 單元測試 | 加解密、錯誤主金鑰、竄改、`kid` 綁定。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../client/ClientRegistrationIntegrationTest.java` | `as-test` | 整合測試 | 註冊、重新啟動時更新、secret 輪換、缺少 secret、停權。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../user/UserAccountIntegrationTest.java` | `as-test` | 整合測試 | 帳號或 Email 登入、失敗訊息一致、停用與鎖定、角色過期、唯一性、密碼政策、重新雜湊、第一位管理員。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*AuthorizationFlowIntegrationTest.java` | `as-test` | 整合測試 | 授權碼 + PKCE 完整流程、Token 的 claim（第一方、第三方、client_credentials、ID Token）、刷新反映角色變更、Session 撤銷／停用／鎖定後拒絕刷新、自訂 claim、Session 連結、刷新輪換、沒有 Session 的授權被拒絕並回滾、登入失敗、標頭、無 PKCE、未註冊 redirect、client_credentials、停權 client、discovery 與 JWKS；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*GoogleLoginIntegrationTest.java` | `as-test` | 整合測試 | T-FED-01／02／04／06、Email 屬於既有帳號時拒絕、登入頁按鈕；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../support/FakeOidcProvider.java` | `as-test` | 測試用 OIDC 提供者 | JDK `HttpServer`：token、JWKS、userinfo。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../autoconfigure/AutoConfigurationOrderingTest.java` | `as-test` | 單元測試 | `beforeName` 列出的類別都存在。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../keys/SigningKeyIntegrationTest.java` | `as-test` | 整合測試 | T-KEY-01、T-KEY-03、輪換期間的公開與簽章、ES256。 |

### core

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `core/jacky917-security-core/` | `core` | 共用 claim 契約 | 純 Java、無任何依賴（enforcer 檢查）。 |
| `.../Jacky917ClaimNames.java` | `core` | claim 名稱常數 | `roles`、`permissions`、`scope`、`scp`、`asid`、`idp`、`client_id`。 |
| `.../Jacky917AuthorityPrefix.java` | `core` | 權限前綴常數 | `ROLE_`、`PERM_`、`SCOPE_`。 |
| `.../TrustLevel.java` | `core` | client 信任等級 | `FIRST_PARTY`／`THIRD_PARTY`（Authorization Server 使用）。 |

### Resource Server

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `resource-server/jacky917-security-resource-server-starter/` | `rs-starter` | 業務 API 引入的 starter | 聚合 autoconfigure 與 annotations。 |
| `resource-server/jacky917-security-annotations/` | `annotations` | 授權註解 | `@RequireRole/@RequirePerm/@RequireScope/@RequireAny/@RequireAll`，皆呼叫 `jacky917AuthorityEvaluator`。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/.../config/Jacky917SecurityAutoConfiguration.java` | `rs-autoconfigure` | 自動配置入口 | filter chain、JWT converter、401/403 JSON；`beforeName` 排在 Boot 安全性自動配置之前；方法級授權一律啟用。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/.../config/Jacky917AuthorityEvaluatorAutoConfiguration.java` | `rs-autoconfigure` | `@Require*` 所需的 Bean | `jacky917AuthorityEvaluator` 與佔位符設定；沒有任何條件，停用 Starter 或非 Servlet 應用程式也會註冊。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/.../authentication/JwtAuthoritiesExtractor.java` | `rs-autoconfigure` | claims → authorities | 讀取 `roles/permissions/scope/scp`，加前綴、去重、排序。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/.../methodsecurity/Jacky917AuthorityEvaluator.java` | `rs-autoconfigure` | 註解的判斷邏輯 | `hasRole/hasPerm/hasScope` 使用設定的前綴；`hasAnyAuthority/hasAllAuthorities`；一律 fail-closed。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/.../properties/Jacky917SecurityProperties.java` | `rs-autoconfigure` | Starter 屬性 | `jacky917.security.*`；`permit-all-patterns` 預設只有 `/actuator/health`。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/main/resources/META-INF/spring/...AutoConfiguration.imports` | `rs-autoconfigure` | 自動配置註冊 | 讓 Spring Boot 載入自動配置。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../JwtAuthoritiesExtractorTest.java` | `rs-test` | 單元測試 | claims 型態、去重、排序、前綴覆寫。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../Jacky917AuthorityEvaluatorTest.java` | `rs-test` | 單元測試 | AND/OR、前綴判斷、fail-closed。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../Jacky917SecurityPropertiesTest.java` | `rs-test` | 單元測試 | 預設 claim 名稱與前綴必須與 core 一致。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../MethodSecurityAnnotationsIntegrationTest.java` | `rs-test` | 整合測試 | 自訂註解的 200/403。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../SecurityBehaviorIntegrationTest.java` | `rs-test` | 整合測試 | 401/403 JSON、`WWW-Authenticate`、放行路徑、註解覆蓋與疊加限制、RFC 9728 端點。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../AutoConfigurationOrderingIntegrationTest.java` | `rs-test` | 整合測試 | `beforeName` 的類別都存在；只有 Starter 的 filter chain 與 JWT converter。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../ErrorResponseJsonMapperIntegrationTest.java` | `rs-test` | 整合測試 | 錯誤回應使用應用程式的 Jackson 3 `JsonMapper`。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../PrefixAndDefaultsIntegrationTest.java` | `rs-test` | 整合測試 | 2.0 行為：註解跟隨前綴、預設不放行 Swagger、`@Secured` 仍生效。 |
| `resource-server/jacky917-security-resource-server-autoconfigure/src/test/.../StarterDisabledIntegrationTest.java` | `rs-test` | 整合測試 | `enabled=false` 且自行啟用方法級授權時註解照常判斷（不是 500）；非 Web 應用程式仍有 evaluator。 |

### Examples（不發佈）

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `examples/example-resource-server/` | `example-rs` | Resource Server 範例 | Web、JPA、MySQL（測試用 H2）、Swagger；port 8080。Java 套件仍為 `jacky917.demo.resourceserver`。 |
| `.../controller/DemoSecureController.java` | `example-rs` | 安全端點 | permitAll、authenticated、RBAC、AND/OR、ABAC。 |
| `.../authz/DemoAuthzConfiguration.java` | `example-rs` | ABAC 規則 | `clip.ownerId == JWT sub`，找不到資料時拒絕。 |
| `.../config/DemoJwtDecoderConfiguration.java` | `example-rs` | JwtDecoder 範例 | HS256 JWK，驗證簽章與 issuer。 |
| `.../tools/GenerateTestJwtMain.java` | `example-rs` | 測試 JWT CLI | 以 demo 金鑰產生 Token。 |
| `examples/example-authorization-server/` | `example-as` | 測試用 Token 簽發服務 | `POST /oauth2/token`，固定密碼 `password`，僅供本地測試；port 8081。 |
| `*/src/main/resources/demo/jwk/demo-hs256.jwk.json` | `examples` | 測試金鑰 | 兩個範例共用的 HS256 JWK。 |

### 文件

| 路徑 (Path) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|
| `README.md` | 專案入口 | 模組、快速開始（BOM）、預設行為、文件導覽、本地開發。 |
| `docs/resource-server/getting-started.md` | 使用指南 | 引入依賴、JwtDecoder、放行路徑、註解、ABAC、錯誤回應、覆寫、測試、上線清單。 |
| `docs/resource-server/configuration.md` | 設定參考 | 所有屬性、預設值、日誌、與 Spring Boot 原生屬性的關係。 |
| `docs/resource-server/limitations.md` | 限制與注意事項 | 已知限制與解法；§3、§14 於 2.0 解決。 |
| `docs/resource-server/troubleshooting.md` | 疑難排解 | 依症狀排查。 |
| `docs/resource-server/jwt-claims.md`、`authorization-model.md` | Token 契約與授權模型 | |
| `docs/guides/upgrade-to-2.0.md` | 升級指南 | 1.x → 2.0 的座標、套件、設定、行為變更與檢查清單。 |
| `docs/guides/e2e-testing.md`、`github-packages.md` | 操作指南 | 端對端驗證；發佈與引用。 |
| `docs/design/v2-overview.md` | 2.0 總設計 | 里程碑、破壞性變更、決策索引。 |
| `docs/design/boot4-migration-design.md`、`repo-structure-design.md` | 2.0 設計 | Boot 4.1 升級與 repo 重構（含實施紀錄）。 |
| `docs/design/auth-server-design.md`、`auth-server-data-model.md`、`auth-server-detailed-design.md` | Authorization Server 設計 | 架構與決策、表設計（PostgreSQL／SQLite 實測）、元件與流程。 |
| `docs/design/starter-design.md` | Resource Server starter 設計 | 自動配置、Bean 清單、擴充點。 |
| `docs/design/refresh-rotation.md`、`database-schema.md` | 早期參考設計 | 已由 AS 設計取代主要內容。 |
| `docs/PROGRESS.md` | 進度追蹤 | 每一步的狀態、命令、決策。 |
| `docs/PROJECT_STRUCTURE.md` | 專案結構 | 本文件。 |
