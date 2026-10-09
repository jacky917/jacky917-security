# 專案結構 (PROJECT STRUCTURE)

本文件使用 `tree -a -I 'target|.git|.idea|.cursor|.flattened-pom.xml|data'` 的輸出來展示目前專案真實結構（`.idea`、`.cursor` 為本機 IDE／工具設定，未納入版本控制；`.flattened-pom.xml` 為建置產物；`data/` 為範例登入服務在本機執行時建立的 SQLite 資料庫）。
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
|   |       |   |               |-- audit
|   |       |   |               |   |-- JdbcLoginAuditListener.java
|   |       |   |               |   |-- LoginAuditEvent.java
|   |       |   |               |   |-- LoginAuditEventType.java
|   |       |   |               |   |-- LoginAuditRepository.java
|   |       |   |               |   `-- LoginFailureReason.java
|   |       |   |               |-- authentication
|   |       |   |               |   |-- LoginAttemptGuard.java
|   |       |   |               |   |-- LoginCompletion.java
|   |       |   |               |   |-- LoginFailureHandler.java
|   |       |   |               |   |-- LoginSuccessHandler.java
|   |       |   |               |   `-- PrincipalNormalizer.java
|   |       |   |               |-- autoconfigure
|   |       |   |               |   |-- AuthorizationServerAutoConfiguration.java
|   |       |   |               |   |-- AuthorizationServerClientsConfiguration.java
|   |       |   |               |   |-- AuthorizationServerDatabaseConfiguration.java
|   |       |   |               |   |-- AuthorizationServerKeysConfiguration.java
|   |       |   |               |   |-- AuthorizationServerMaintenanceConfiguration.java
|   |       |   |               |   |-- AuthorizationServerObservabilityAutoConfiguration.java
|   |       |   |               |   |-- AuthorizationServerSecurityConfiguration.java
|   |       |   |               |   |-- AuthorizationServerSessionRegistryAutoConfiguration.java
|   |       |   |               |   `-- AuthorizationServerUsersConfiguration.java
|   |       |   |               |-- client
|   |       |   |               |   |-- ActiveClientRegisteredClientRepository.java
|   |       |   |               |   |-- ClientProfile.java
|   |       |   |               |   |-- ClientProfileRepository.java
|   |       |   |               |   |-- ClientRegistrationSynchronizer.java
|   |       |   |               |   `-- ClientStatus.java
|   |       |   |               |-- database
|   |       |   |               |   |-- AuthorizationServerDialect.java
|   |       |   |               |   |-- AuthorizationServerDialects.java
|   |       |   |               |   |-- AuthorizationServerMigrations.java
|   |       |   |               |   |-- AuthorizationServerMigrationsDetector.java
|   |       |   |               |   |-- DefaultSqliteEnvironmentPostProcessor.java
|   |       |   |               |   |-- PostgresqlDialect.java
|   |       |   |               |   |-- SqliteDialect.java
|   |       |   |               |   |-- SqliteExceptionTranslator.java
|   |       |   |               |   `-- SqliteExceptionTranslatorPostProcessor.java
|   |       |   |               |-- federation
|   |       |   |               |   |-- FederatedIdentityService.java
|   |       |   |               |   |-- FederatedLoginRejectedException.java
|   |       |   |               |   |-- FederatedLoginSuccessHandler.java
|   |       |   |               |   |-- FederatedUserInfo.java
|   |       |   |               |   |-- FederatedUserInfoMapper.java
|   |       |   |               |   |-- GitHubFederatedUserInfoMapper.java
|   |       |   |               |   |-- LineIdTokens.java
|   |       |   |               |   |-- LinkIntent.java
|   |       |   |               |   |-- LinkedIdentity.java
|   |       |   |               |   |-- OidcFederatedUserInfoMapper.java
|   |       |   |               |   `-- PendingLinkService.java
|   |       |   |               |-- keys
|   |       |   |               |   |-- ActiveKeyJwtEncoder.java
|   |       |   |               |   |-- JdbcSigningKeyStore.java
|   |       |   |               |   |-- KeyEncryptor.java
|   |       |   |               |   |-- RotatingJwkSource.java
|   |       |   |               |   |-- SigningKey.java
|   |       |   |               |   |-- SigningKeyService.java
|   |       |   |               |   |-- SigningKeyStatus.java
|   |       |   |               |   `-- SigningKeyStore.java
|   |       |   |               |-- maintenance
|   |       |   |               |   |-- DataCleanup.java
|   |       |   |               |   |-- DataCleanupEvent.java
|   |       |   |               |   |-- MaintenanceScheduler.java
|   |       |   |               |   |-- ScheduledJobLock.java
|   |       |   |               |   `-- SigningKeyRotation.java
|   |       |   |               |-- observability
|   |       |   |               |   |-- AuthorizationServerMetrics.java
|   |       |   |               |   `-- SigningKeyHealthIndicator.java
|   |       |   |               |-- properties
|   |       |   |               |   `-- AuthorizationServerProperties.java
|   |       |   |               |-- refresh
|   |       |   |               |   |-- RefreshTokenHistoryRepository.java
|   |       |   |               |   |-- RefreshTokenRejectedEvent.java
|   |       |   |               |   |-- RefreshTokenReuseDetector.java
|   |       |   |               |   |-- ReuseDetectingRefreshTokenProvider.java
|   |       |   |               |   `-- RotatedRefreshToken.java
|   |       |   |               |-- session
|   |       |   |               |   |-- AuthSession.java
|   |       |   |               |   |-- AuthSessionService.java
|   |       |   |               |   |-- AuthSessionStatus.java
|   |       |   |               |   |-- Jacky917LogoutHandler.java
|   |       |   |               |   |-- LoginMethod.java
|   |       |   |               |   |-- LoginSessionValidationFilter.java
|   |       |   |               |   |-- RevokeReason.java
|   |       |   |               |   |-- SessionAuthorizationRepository.java
|   |       |   |               |   `-- SessionLinkingAuthorizationService.java
|   |       |   |               |-- support
|   |       |   |               |   |-- Columns.java
|   |       |   |               |   |-- Hashes.java
|   |       |   |               |   `-- UuidV7.java
|   |       |   |               |-- token
|   |       |   |               |   |-- AccessTokenIssuedEvent.java
|   |       |   |               |   |-- AudienceResolver.java
|   |       |   |               |   |-- AuthorityResolver.java
|   |       |   |               |   |-- ConfiguredAudienceResolver.java
|   |       |   |               |   |-- DefaultAuthorityResolver.java
|   |       |   |               |   |-- Jacky917TokenCustomizer.java
|   |       |   |               |   |-- ResolvedAuthorities.java
|   |       |   |               |   `-- TokenClaimsContributor.java
|   |       |   |               |-- user
|   |       |   |               |   |-- BootstrapAdminInitializer.java
|   |       |   |               |   |-- Jacky917UserDetailsService.java
|   |       |   |               |   |-- JdbcUserAccountService.java
|   |       |   |               |   |-- NewUser.java
|   |       |   |               |   |-- PasswordPolicy.java
|   |       |   |               |   |-- UserAccount.java
|   |       |   |               |   |-- UserAccountService.java
|   |       |   |               |   |-- UserAuthorities.java
|   |       |   |               |   `-- UserStatus.java
|   |       |   |               `-- web
|   |       |   |                   |-- AccountController.java
|   |       |   |                   |-- AccountLinkController.java
|   |       |   |                   |-- IdentityProviders.java
|   |       |   |                   |-- LoginController.java
|   |       |   |                   `-- PageSupport.java
|   |       |   `-- resources
|   |       |       |-- META-INF
|   |       |       |   |-- spring
|   |       |       |   |   `-- org.springframework.boot.autoconfigure.AutoConfiguration.imports
|   |       |       |   `-- spring.factories
|   |       |       |-- db
|   |       |       |   `-- jacky917-as
|   |       |       |       |-- postgresql
|   |       |       |       |   |-- V1_0_0__identity.sql
|   |       |       |       |   |-- V1_0_1__authorization_model.sql
|   |       |       |       |   |-- V1_0_2__oauth2_official.sql
|   |       |       |       |   |-- V1_0_3__oauth2_extensions.sql
|   |       |       |       |   |-- V1_0_4__sessions.sql
|   |       |       |       |   |-- V1_0_5__security.sql
|   |       |       |       |   `-- V1_0_6__seed.sql
|   |       |       |       `-- sqlite
|   |       |       |           |-- V1_0_0__identity.sql
|   |       |       |           |-- V1_0_1__authorization_model.sql
|   |       |       |           |-- V1_0_2__oauth2_official.sql
|   |       |       |           |-- V1_0_3__oauth2_extensions.sql
|   |       |       |           |-- V1_0_4__sessions.sql
|   |       |       |           |-- V1_0_5__security.sql
|   |       |       |           `-- V1_0_6__seed.sql
|   |       |       |-- jacky917
|   |       |       |   |-- authorization-server-messages.properties
|   |       |       |   `-- authorization-server-messages_zh_TW.properties
|   |       |       |-- static
|   |       |       |   `-- jacky917
|   |       |       |       `-- authorization-server.css
|   |       |       `-- templates
|   |       |           `-- jacky917
|   |       |               |-- account.html
|   |       |               |-- link-account.html
|   |       |               |-- login.html
|   |       |               `-- signed-in.html
|   |       `-- test
|   |           |-- java
|   |           |   `-- jacky917
|   |           |       `-- security
|   |           |           `-- authorizationserver
|   |           |               |-- authentication
|   |           |               |   |-- LoginAttemptGuardTest.java
|   |           |               |   |-- LoginFailureHandlerTest.java
|   |           |               |   `-- PrincipalNormalizerTest.java
|   |           |               |-- autoconfigure
|   |           |               |   |-- AutoConfigurationOrderingTest.java
|   |           |               |   `-- SessionRegistryAutoConfigurationTest.java
|   |           |               |-- client
|   |           |               |   `-- ClientRegistrationIntegrationTest.java
|   |           |               |-- database
|   |           |               |   |-- DatabaseMigrationIntegrationTest.java
|   |           |               |   |-- DefaultSqliteEnvironmentPostProcessorTest.java
|   |           |               |   |-- DefaultSqliteIntegrationTest.java
|   |           |               |   |-- SchemaConsistencyIntegrationTest.java
|   |           |               |   |-- SchemaIntrospection.java
|   |           |               |   |-- SqliteExceptionTranslatorTest.java
|   |           |               |   `-- SqliteValidationIntegrationTest.java
|   |           |               |-- federation
|   |           |               |   |-- FederatedLoginSuccessHandlerTest.java
|   |           |               |   |-- GitHubFederatedUserInfoMapperTest.java
|   |           |               |   `-- OidcFederatedUserInfoMapperTest.java
|   |           |               |-- flow
|   |           |               |   |-- AbstractAccountLinkingIntegrationTest.java
|   |           |               |   |-- AbstractAuthorizationFlowIntegrationTest.java
|   |           |               |   |-- AbstractFlowIntegrationTest.java
|   |           |               |   |-- AbstractGoogleIntegrationTest.java
|   |           |               |   |-- AbstractGoogleLoginIntegrationTest.java
|   |           |               |   |-- AbstractLoginProtectionIntegrationTest.java
|   |           |               |   |-- AbstractLogoutIntegrationTest.java
|   |           |               |   |-- AbstractMaintenanceIntegrationTest.java
|   |           |               |   |-- ExternalProvidersIntegrationTest.java
|   |           |               |   |-- ManualOnlyAccountLinkingIntegrationTest.java
|   |           |               |   |-- ObservabilityIntegrationTest.java
|   |           |               |   |-- PostgresqlAccountLinkingIntegrationTest.java
|   |           |               |   |-- PostgresqlAuthorizationFlowIntegrationTest.java
|   |           |               |   |-- PostgresqlGoogleLoginIntegrationTest.java
|   |           |               |   |-- PostgresqlLoginProtectionIntegrationTest.java
|   |           |               |   |-- PostgresqlLogoutIntegrationTest.java
|   |           |               |   |-- PostgresqlMaintenanceIntegrationTest.java
|   |           |               |   |-- SqliteAccountLinkingIntegrationTest.java
|   |           |               |   |-- SqliteAuthorizationFlowIntegrationTest.java
|   |           |               |   |-- SqliteEs256AuthorizationFlowIntegrationTest.java
|   |           |               |   |-- SqliteGoogleLoginIntegrationTest.java
|   |           |               |   |-- SqliteLoginProtectionIntegrationTest.java
|   |           |               |   |-- SqliteLogoutIntegrationTest.java
|   |           |               |   `-- SqliteMaintenanceIntegrationTest.java
|   |           |               |-- keys
|   |           |               |   |-- ActiveKeyJwtEncoderTest.java
|   |           |               |   |-- KeyEncryptorTest.java
|   |           |               |   `-- SigningKeyIntegrationTest.java
|   |           |               |-- maintenance
|   |           |               |   `-- MaintenanceSchedulerTest.java
|   |           |               |-- observability
|   |           |               |   `-- SigningKeyHealthIndicatorTest.java
|   |           |               |-- properties
|   |           |               |   `-- AuthorizationServerPropertiesTest.java
|   |           |               |-- refresh
|   |           |               |   `-- RefreshTokenReuseDetectorTest.java
|   |           |               |-- session
|   |           |               |   |-- Jacky917LogoutHandlerTest.java
|   |           |               |   |-- LoginSessionValidationFilterTest.java
|   |           |               |   `-- SessionLinkingAuthorizationServiceTest.java
|   |           |               |-- support
|   |           |               |   |-- ColumnsTest.java
|   |           |               |   |-- FakeGitHub.java
|   |           |               |   |-- FakeOidcProvider.java
|   |           |               |   |-- MutableClock.java
|   |           |               |   |-- TestDatabases.java
|   |           |               |   `-- UuidV7Test.java
|   |           |               |-- token
|   |           |               |   `-- Jacky917TokenCustomizerTest.java
|   |           |               |-- user
|   |           |               |   `-- UserAccountIntegrationTest.java
|   |           |               `-- web
|   |           |                   `-- LoginControllerTest.java
|   |           `-- resources
|   |               `-- app-migrations
|   |                   `-- V1__app_note.sql
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
|   |-- authorization-server
|   |   `-- getting-started.md
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
|-- e2e-tests
|   |-- pom.xml
|   `-- src
|       `-- test
|           `-- java
|               `-- jacky917
|                   `-- e2e
|                       |-- Browser.java
|                       `-- EndToEndTest.java
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
|   |       |   |               `-- DemoDataInitializer.java
|   |       |   `-- resources
|   |       |       `-- application.yml
|   |       `-- test
|   |           |-- java
|   |           |   `-- jacky917
|   |           |       `-- demo
|   |           |           `-- authorizationserver
|   |           |               `-- DemoAuthorizationServerIntegrationTest.java
|   |           `-- resources
|   |               `-- config
|   |                   `-- application.yml
|   |-- example-bff
|   |   |-- pom.xml
|   |   `-- src
|   |       |-- main
|   |       |   |-- java
|   |       |   |   `-- jacky917
|   |       |   |       `-- demo
|   |       |   |           `-- bff
|   |       |   |               |-- BffApplication.java
|   |       |   |               |-- BffController.java
|   |       |   |               |-- BffProperties.java
|   |       |   |               |-- BffSecurityConfiguration.java
|   |       |   |               `-- SerializedAuthorizedClientManager.java
|   |       |   `-- resources
|   |       |       |-- application.yml
|   |       |       `-- static
|   |       |           |-- bff.js
|   |       |           `-- index.html
|   |       `-- test
|   |           `-- java
|   |               `-- jacky917
|   |                   `-- demo
|   |                       `-- bff
|   |                           |-- BffApplicationTest.java
|   |                           `-- BffControllerProxyTest.java
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
|           |   |               |   `-- DemoSwaggerConfiguration.java
|           |   |               `-- controller
|           |   |                   `-- DemoSecureController.java
|           |   `-- resources
|           |       `-- application.yml
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

166 directories, 203 files
```

---
## 檔案用途說明

### 建置與 CI

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `pom.xml` | `parent` | 根 POM（aggregator + 建置設定） | 繼承 `spring-boot-starter-parent:4.1.1`；`${revision}` 統一版本；flatten 產生不含 parent 的發佈 POM；enforcer 依賴方向規則；Lombok 與 configuration-processor 的 annotation processor。 |
| `jacky917-security-bom/pom.xml` | `bom` | BOM | 列出所有發佈模組的版本（Authorization Server 於 2.1.0 加入）；flatten 以 bom 模式發佈。 |
| `relocation/jacky917-security-starter/pom.xml` | `relocation` | 舊座標 relocation | `com.github.jacky917:jacky917-security-starter` → 新的 resource server starter；只在 2.0.x 發佈。 |
| `.github/workflows/ci.yml` | `ci` | 持續整合 | push 到 `main`／`1.x` 與所有 PR：Java 21、25 建置與測試；文件連結檢查。 |
| `.github/workflows/publish.yml` | `ci` | 發佈流程 | Release 時檢查 tag 等於 `revision`、已宣告授權條款；整個 reactor 測試通過後才部署到 GitHub Packages。 |
| `scripts/has-declared-license.py` | `tooling` | 授權條款檢查 | 以 XML 解析確認 `pom.xml` 自行宣告了授權條款（發佈流程使用）。 |
| `scripts/check-doc-links.py` | `tooling` | 文件檢查 | README 與 docs 的相對連結（含標題與 `<...>` 寫法）、錨點（重複標題依 GitHub 規則加 `-1`）、YAML 範例；有問題即非 0 結束。 |

### Authorization Server（2.1.0 起發佈）

| 路徑 (Path) | 模組 (Module) | 用途 (Purpose) | 關鍵說明 (Key Notes) |
|---|---|---|---|
| `authorization-server/jacky917-security-authorization-server-starter/` | `as-starter` | 登入服務引入的 starter | 聚合 AS autoconfigure；2.1.0 起發佈並加入 BOM。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerAutoConfiguration.java` | `as-autoconfigure` | 自動配置入口 | `enabled=false` 時停用；在 DataSource 之後執行。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerDatabaseConfiguration.java` | `as-autoconfigure` | 資料庫配置（D22） | 選擇並驗證 dialect；SQLite 例外轉換。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../properties/AuthorizationServerProperties.java` | `as-autoconfigure` | 設定屬性 | `jacky917.security.authorization-server.*`；實作 `Validator`，設定錯誤時啟動失敗。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/AuthorizationServerDialect.java` | `as-autoconfigure` | 資料庫方言 SPI | `PostgresqlDialect`、`SqliteDialect`；`AuthorizationServerDialects` 依 URL 選擇。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/SqliteDialect.java` | `as-autoconfigure` | SQLite 方言 | 檢查必要連線參數、PRAGMA、Hikari 自動提交；缺少即啟動失敗。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/DefaultSqliteEnvironmentPostProcessor.java` | `as-autoconfigure` | 預設值 | 未設定 datasource 時使用 SQLite；應用程式 Flyway 的 baseline 預設值；預設檔案在寫入機密前設為 600。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/SqliteExceptionTranslator.java` | `as-autoconfigure` | SQLite 例外轉換 | 約束違反轉為 `DuplicateKeyException` 等；由 `SqliteExceptionTranslatorPostProcessor` 套用到 `JdbcTemplate`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerKeysConfiguration.java` | `as-autoconfigure` | 簽章金鑰配置 | 首次啟動產生金鑰；`JWKSource`（只有公鑰）與只用 `ACTIVE` 私鑰的 `JwtEncoder`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/SigningKeyService.java` | `as-autoconfigure` | 金鑰服務 | 產生 RS256／ES256 金鑰、快取 1 分鐘、啟動時確認可解密。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/KeyEncryptor.java` | `as-autoconfigure` | 私鑰加密 | AES-256-GCM，`kid` 為附加驗證資料。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/SigningKeyStore.java`、`JdbcSigningKeyStore.java` | `as-autoconfigure` | 金鑰儲存 SPI | 預設 `signing_key` 表，可換成 KMS。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/ActiveKeyJwtEncoder.java` | `as-autoconfigure` | Token 簽章 | 一律以目前金鑰與其演算法簽章（RS256／ES256）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../support/Columns.java` | `as-autoconfigure` | 欄位長度 | 外部來源值的欄位長度上限與截斷（不切斷 emoji）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../keys/RotatingJwkSource.java` | `as-autoconfigure` | JWKS | 公開 `NEXT`、`ACTIVE`、`RETIRING` 的公鑰。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerObservabilityAutoConfiguration.java` | `as-autoconfigure` | 監控配置（§8） | 有 `MeterRegistry` 時註冊 metrics；有 Spring Boot 健康檢查時註冊 `signingKey`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../observability/AuthorizationServerMetrics.java`、`SigningKeyHealthIndicator.java` | `as-autoconfigure` | Metrics、健康檢查 | 由事件計數（登入、簽發、刷新拒絕、清理）；gauge（有效 Session、金鑰使用天數）；沒有 `ACTIVE` 金鑰時 `DOWN`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../token/AccessTokenIssuedEvent.java`、`refresh/RefreshTokenRejectedEvent.java`、`maintenance/DataCleanupEvent.java` | `as-autoconfigure` | 事件 | 供 metrics 與應用程式監聽。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerSessionRegistryAutoConfiguration.java` | `as-autoconfigure` | 多實例（D10） | 應用程式使用 Spring Session 時，OIDC 的 Session registry 改讀共用的 Session 儲存（跨實例時 ID Token 才有 `sid`）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../autoconfigure/AuthorizationServerMaintenanceConfiguration.java` | `as-autoconfigure` | 排程配置 | 金鑰輪換（每小時）、清理（15 分鐘、每小時、每天）；`keys.rotation-enabled`、`cleanup.enabled`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../maintenance/SigningKeyRotation.java` | `as-autoconfigure` | 金鑰輪換（§5.7） | `NEXT` 預告 → 啟用（舊金鑰 `RETIRING`）→ 退役；每一步先檢查狀態。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../maintenance/DataCleanup.java` | `as-autoconfigure` | 清理（§5.8、資料模型 §14.1） | 授權、Refresh Token 歷史、登入 Session、操作 token、稽核、退役金鑰；分批刪除。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../maintenance/ScheduledJobLock.java`、`MaintenanceScheduler.java` | `as-autoconfigure` | 排程 | `shedlock` 表的鎖（每個週期一個實例）；自己的執行緒，不啟用 `@Scheduled`。 |
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
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedLoginSuccessHandler.java` | `as-autoconfigure` | 第三方登入成功 | 轉換使用者、找到或建立帳號並登入；Email 屬於既有帳號時保存待確認的連結並導向確認頁；從帳號頁發起時連結並還原原本的登入；完成同一位使用者的待確認連結；移除提供者的 token。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedIdentityService.java`、`LinkedIdentity.java` | `as-autoconfigure` | 外部帳號 | 已連結 → 登入；已驗證的 Email 屬於既有帳號 → `LINK_REQUIRED`（或 `manual-only` 時 `ACCOUNT_EXISTS`）；其餘建立新使用者。連結、列出、解除連結（保留最後一種登入方式）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/PendingLinkService.java`、`LinkIntent.java` | `as-autoconfigure` | 待確認的連結 | `user_action_token`（`LINK_ACCOUNT`，10 分鐘、只用一次、只存雜湊）；帳號頁發起連結時存在瀏覽器 Session 的請求。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/AccountLinkController.java`、`templates/jacky917/link-account.html` | `as-autoconfigure` | 連結確認頁 | `/jacky917/link-account`：原帳號密碼（計入鎖定與限流）或已連結的提供者確認；取消。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/IdentityProviders.java` | `as-autoconfigure` | 提供者清單 | 登入頁與帳號頁共用；`login.providers` 或依名稱排序。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/LoginCompletion.java` | `as-autoconfigure` | 完成登入 | 建立登入 Session、以標準 principal 登入瀏覽器、發布 `LOGIN`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../support/Hashes.java` | `as-autoconfigure` | 雜湊 | 一次性秘密值的 SHA-256（Refresh Token 歷史、連結 token）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/FederatedUserInfoMapper.java`、`OidcFederatedUserInfoMapper.java`、`FederatedUserInfo.java` | `as-autoconfigure` | 提供者資料轉換 SPI | 通用 OIDC（Google、LINE 等）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/GitHubFederatedUserInfoMapper.java` | `as-autoconfigure` | GitHub | 數字 `id` 為 subject；`/user/emails` 中主要且已驗證的 Email。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../federation/LineIdTokens.java` | `as-autoconfigure` | LINE | ID Token 以 channel secret 驗證 HS256（`JwtDecoderFactory` Bean）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/PrincipalNormalizer.java` | `as-autoconfigure` | D16 | 轉為 `UsernamePasswordAuthenticationToken` + `User(使用者 ID)`；補上 factor authority。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/LoginSuccessHandler.java` | `as-autoconfigure` | 登入成功 | 記錄登入、建立 `auth_session`、發布 `LOGIN`、回到授權請求。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/LoginFailureHandler.java` | `as-autoconfigure` | 登入失敗（§5.1） | 密碼錯誤時計數，達上限鎖定並發布 `ACCOUNT_LOCKED`；稽核失敗原因；一律導向 `/login?error`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../authentication/LoginAttemptGuard.java` | `as-autoconfigure` | IP 限流（§5.1） | `POST /login` 前檢查該 IP 最近一分鐘的失敗次數。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../audit/LoginAuditRepository.java`、`LoginFailureReason.java` | `as-autoconfigure` | 稽核查詢 | 依 IP 計算失敗次數（資料模型 §11.7）；失敗原因代碼。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/LoginController.java` | `as-autoconfigure` | 登入頁 | 依語言顯示；所有錯誤顯示相同訊息；`/jacky917/theme.css`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/main/resources/templates/jacky917/`、`static/jacky917/`、`jacky917/authorization-server-messages*.properties` | `as-autoconfigure` | 登入頁資源 | Thymeleaf 範本、樣式、英文與繁體中文訊息。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/main/resources/db/jacky917-as/{postgresql,sqlite}/` | `as-autoconfigure` | Flyway V1 | 兩種資料庫各 7 個同名檔案：23 張表與內建資料。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../database/AuthorizationServerMigrations.java`、`AuthorizationServerMigrationsDetector.java` | `as-autoconfigure` | Migration 執行 | Starter 自己的 Flyway 與歷史表 `jacky917_as_schema_history`；讓依賴資料庫的 Bean 在 migration 之後建立。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/LoginSessionValidationFilter.java` | `as-autoconfigure` | 登入 Session 檢查 | 登入 Session 已失效時結束瀏覽器登入，授權請求回到登入頁。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../refresh/RefreshTokenReuseDetector.java`、`ReuseDetectingRefreshTokenProvider.java` | `as-autoconfigure` | 重用偵測（§5.4、D19） | 包裝 Spring 的刷新 provider：列鎖、刷新前檢查 Session 與使用者、記錄舊 token；寬限期後重用即撤銷 Session。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../refresh/RefreshTokenHistoryRepository.java`、`RotatedRefreshToken.java` | `as-autoconfigure` | 已輪換的 token | `refresh_token_history`：只存 SHA-256，保留至 `min(token 到期, 輪換 + 保留期)`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/RevokeReason.java` | `as-autoconfigure` | 撤銷原因 | `AuthSessionService#revoke`／`revokeAll` 撤銷 Session 並在同一個交易中刪除其授權（資料模型 §11.4、§11.5）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../session/Jacky917LogoutHandler.java` | `as-autoconfigure` | 登出（§5.5） | RP-Initiated Logout 與 `POST /logout`：從瀏覽器與 `id_token_hint` 找出登入 Session 並撤銷、發布 `LOGOUT`。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/AccountController.java`、`templates/jacky917/account.html` | `as-autoconfigure` | 帳號頁 | `/jacky917/account`：登入中的裝置、登出單一或所有裝置；已連結的帳號、連結與解除連結。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../web/PageSupport.java` | `as-autoconfigure` | 頁面共用 | Starter 自己的訊息檔與品牌設定。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/.../audit/LoginAuditEvent.java`、`LoginAuditEventType.java`、`JdbcLoginAuditListener.java` | `as-autoconfigure` | 稽核（§8.1） | 元件在交易提交後發布事件；listener 寫入 `login_audit`，失敗只記錄日誌。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../support/TestDatabases.java` | `as-test` | 測試資料庫 | SQLite 暫存檔；embedded PostgreSQL 16（不需 Docker）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../database/*IntegrationTest.java` | `as-test` | 整合測試 | migration、官方 JDBC 類別相容性、約束、schema 一致性、SQLite 設定檢查、預設 SQLite。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../properties/AuthorizationServerPropertiesTest.java` | `as-test` | 單元測試 | 預設值、issuer、有效期、寬限期與保留期、主金鑰驗證。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../refresh/RefreshTokenReuseDetectorTest.java` | `as-test` | 單元測試 | 重用偵測的每個分支（未知、寬限期內外、Session 與使用者狀態、記錄與保留期）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/AbstractFlowIntegrationTest.java` | `as-test` | 測試共用 | `@SpringBootTest` 設定與模擬瀏覽器、BFF 的工具（登入、換 Token、刷新、Session 斷言）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*LogoutIntegrationTest.java` | `as-test` | 整合測試 | T-LOGOUT-01～04、`POST /logout`、帳號頁（裝置清單、登出其他／目前／所有裝置、不能登出他人的 Session、CSRF）；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../session/Jacky917LogoutHandlerTest.java` | `as-test` | 單元測試 | 從瀏覽器與 `id_token_hint` 找 Session 的每個分支。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*LoginProtectionIntegrationTest.java` | `as-test` | 整合測試 | 連續失敗鎖定（不延長、到期後恢復）、成功歸零與稽核、IP 限流、不存在與停用的帳號；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../authentication/LoginAttemptGuardTest.java`、`LoginFailureHandlerTest.java` | `as-test` | 單元測試 | 限流與每個失敗原因的分支。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../keys/KeyEncryptorTest.java` | `as-test` | 單元測試 | 加解密、錯誤主金鑰、竄改、`kid` 綁定。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../client/ClientRegistrationIntegrationTest.java` | `as-test` | 整合測試 | 註冊、重新啟動時更新、secret 輪換、缺少 secret、停權。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../user/UserAccountIntegrationTest.java` | `as-test` | 整合測試 | 帳號或 Email 登入、失敗訊息一致、停用與鎖定、角色過期、唯一性、密碼政策、重新雜湊、第一位管理員。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*AuthorizationFlowIntegrationTest.java` | `as-test` | 整合測試 | 授權碼 + PKCE 完整流程、Token 的 claim（第一方、第三方、client_credentials、ID Token）、刷新反映角色變更、Session 撤銷／停用／變更密碼後拒絕刷新（並撤銷）、暫時鎖定不影響刷新、重用偵測（T-REFRESH-01～03：記錄舊 token、寬限期內外、併發刷新依序執行）、自訂 claim、Session 連結、刷新輪換、沒有 Session 的授權被拒絕並回滾、登入失敗、標頭、無 PKCE、未註冊 redirect、client_credentials、停權 client、discovery 與 JWKS；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*GoogleLoginIntegrationTest.java` | `as-test` | 整合測試 | T-FED-01／02／04／06、Email 屬於既有帳號時拒絕、登入頁按鈕；SQLite 與 PostgreSQL 各一次。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/AbstractGoogleIntegrationTest.java` | `as-test` | 測試共用 | 假的 Google（另有 `google-work` registration）與第三方登入流程的工具、可推移的時鐘。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*AccountLinkingIntegrationTest.java` | `as-test` | 整合測試 | 以密碼確認（錯誤計數）、取消與到期、以已連結的提供者確認、帳號頁連結與解除連結、連結他人帳號被拒、不能解除唯一的登入方式、`manual-only`；SQLite 與 PostgreSQL。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/ExternalProvidersIntegrationTest.java`、`support/FakeGitHub.java` | `as-test` | 整合測試 | 假的 GitHub（OAuth 2.0）與 LINE（HS256）：主要且已驗證的 Email、沒有 `user:email`、Email 屬於既有帳號、LINE 的 HS256 與未驗證的 Email、登入頁按鈕。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/*MaintenanceIntegrationTest.java` | `as-test` | 整合測試 | T-KEY-02（預告、啟用、退役與舊 token 的驗證）、T-CLEAN-01、Session 的過期與刪除、其他資料的清理與小批次、排程鎖；SQLite 與 PostgreSQL。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../maintenance/MaintenanceSchedulerTest.java` | `as-test` | 單元測試 | 第一次執行時間、取得鎖才執行、失敗不拋出。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../autoconfigure/SessionRegistryAutoConfigurationTest.java` | `as-test` | 單元測試 | 有 Spring Session 時註冊共用的 registry；沒有或停用時不註冊。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/ObservabilityIntegrationTest.java`、`observability/SigningKeyHealthIndicatorTest.java` | `as-test` | 整合與單元測試 | 以實際的登入、刷新、重用驗證每個 metric 與 gauge；健康檢查的 UP／DOWN 與逾期標示。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../federation/GitHubFederatedUserInfoMapperTest.java` | `as-test` | 單元測試 | 支援的 registration、缺少 id、沒有 access token。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../support/FakeOidcProvider.java` | `as-test` | 測試用 OIDC 提供者 | JDK `HttpServer`：token、JWKS、userinfo；每個測試類別各自啟動與關閉，每次登入以授權碼區分。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../support/MutableClock.java` | `as-test` | 可推移的時鐘 | 測試到期行為（Session 90 天、登入 Session 過期）。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../{token,session,federation,authentication,database,support}/*Test.java` | `as-test` | 單元測試 | `Jacky917TokenCustomizer`、`SessionLinkingAuthorizationService`、`LoginSessionValidationFilter`、`PrincipalNormalizer`、`OidcFederatedUserInfoMapper`、`FederatedLoginSuccessHandler`、`SqliteExceptionTranslator`、`DefaultSqliteEnvironmentPostProcessor`、`UuidV7`：Mockito、固定時鐘、每個分支一個案例。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../web/LoginControllerTest.java`、`keys/ActiveKeyJwtEncoderTest.java`、`support/ColumnsTest.java` | `as-test` | 單元測試 | 登入頁的提供者按鈕、以目前金鑰的演算法簽章、截斷。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/.../flow/SqliteEs256AuthorizationFlowIntegrationTest.java` | `as-test` | 整合測試 | 以 ES256 金鑰完整執行授權流程。 |
| `authorization-server/jacky917-security-authorization-server-autoconfigure/src/test/resources/app-migrations/` | `as-test` | 應用程式自己的 migration | 驗證與 Starter 的 migration 並存（歷史表分開）。 |
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
| `examples/example-resource-server/` | `example-rs` | Resource Server 範例 | Web、JPA、MySQL（測試用 H2）、Swagger；port 8080；以登入服務的 JWKS 驗證 Token，並檢查 `iss` 與 `aud`。 |
| `.../controller/DemoSecureController.java` | `example-rs` | 安全端點 | permitAll、authenticated、RBAC、AND/OR、ABAC。 |
| `.../authz/DemoAuthzConfiguration.java` | `example-rs` | ABAC 規則 | `clip.ownerId == JWT sub`，找不到資料時拒絕。 |
| `examples/example-authorization-server/` | `example-as` | 登入服務範例 | 以 AS starter 建立；port 9000；預設 SQLite（`data/`）；Cookie 名稱 `JACKY917_AS_SESSION`。 |
| `.../DemoDataInitializer.java` | `example-as` | 示範資料 | 角色 `A`（權限 `bb`、`clip:read`）、使用者 alice（角色 A）與 bob。 |
| `examples/example-bff/` | `example-bff` | BFF 範例 | port 8082；oauth2Login、`/me`、`/api/**` 代理到 Resource Server（自動附帶並刷新 Access Token）、RP-Initiated Logout。 |
| `.../SerializedAuthorizedClientManager.java` | `example-bff` | 刷新依序執行 | 同一位使用者同時只有一個請求刷新 Token（D19 的 BFF 端）；固定 64 個鎖，記憶體不隨使用者增加。 |
| `.../src/test/.../BffControllerProxyTest.java` | `example-bff` | 代理測試 | 路徑與 query 原樣轉送、拒絕 `//` 開頭的路徑、狀態碼轉回（以本機的假 API 伺服器驗證）。 |
| `.../src/main/resources/static/` | `example-bff` | 示範頁面 | 登入、呼叫 API、登出（CSRF token 以標頭送出）。 |
| `e2e-tests/` | `e2e-tests` | 端對端測試 | 同一個 JVM 啟動登入服務（SQLite + Spring Session JDBC）、兩個 Resource Server、BFF；模擬瀏覽器走完登入、呼叫 API、audience 檢查、登出。 |
| `e2e-tests/.../MultiInstanceEndToEndTest.java`、`RoundRobinProxy.java` | `e2e-tests` | 多實例測試 | 兩個登入服務共用 PostgreSQL（embedded），前面是輪流轉送、沒有黏性的代理；登入、授權碼、換 Token、帳號頁、登出都跨實例。 |
| `e2e-tests/.../E2eApplications.java` | `e2e-tests` | 測試工具 | 啟動範例應用程式（關閉其他範例的自動配置，不載入 application.yml）。 |

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
| `docs/authorization-server/getting-started.md` | Authorization Server 使用指南 | 建立登入服務、設定參考、資料庫、client、Google 登入、Token 內容、限制、上線清單。 |
| `docs/guides/e2e-testing.md`、`github-packages.md` | 操作指南 | 端對端驗證（自動與手動）；發佈與引用。 |
| `docs/design/v2-overview.md` | 2.0 總設計 | 里程碑、破壞性變更、決策索引。 |
| `docs/design/boot4-migration-design.md`、`repo-structure-design.md` | 2.0 設計 | Boot 4.1 升級與 repo 重構（含實施紀錄）。 |
| `docs/design/auth-server-design.md`、`auth-server-data-model.md`、`auth-server-detailed-design.md` | Authorization Server 設計 | 架構與決策、表設計（PostgreSQL／SQLite 實測）、元件與流程。 |
| `docs/design/starter-design.md` | Resource Server starter 設計 | 自動配置、Bean 清單、擴充點。 |
| `docs/design/refresh-rotation.md`、`database-schema.md` | 早期參考設計 | 已由 AS 設計取代主要內容。 |
| `docs/PROGRESS.md` | 進度追蹤 | 每一步的狀態、命令、決策。 |
| `docs/PROJECT_STRUCTURE.md` | 專案結構 | 本文件。 |
