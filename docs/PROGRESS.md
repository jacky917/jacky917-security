# 專案進度追蹤 (PROGRESS)

本文件用於追蹤 `jacky917-security-starter` 的開發進度、決策與變更歷史。
**每一次執行操作後，都必須更新此文件。**

---
## 總體進度
- [🟢] Step 0: 專案初始化與文件奠基
- [🟢] Step 1: 建立 Maven Multi-Module 骨架
- [🟢] Step 2: 引入 Spring Boot & Security 依賴並實作基礎 AutoConfiguration
- [🟢] Step 3: JWT claims -> authorities 完整合併與單元測試
- [🟢] Step 4: 自訂註解（裝飾器）+ 方法級授權測試
- [🟢] Step 5: demo-resource-server（可跑、可 curl、可測）
- [🟢] Step 6: 實作 Demo Auth Server 與 E2E 測試流程
- [🟢] Step 7: 補齊 Refresh Token Rotation 設計與資料表 Schema
- [🟢] Step 8: 引入 Swagger UI 與 MySQL 資料庫情境
- [🟢] Step 9: 程式碼審查、Bug 修正、雙語 JavaDoc 與完整使用文件
- [🟡] Step 10: Authorization Server 設計（方案 C，支援第三方登入）— 設計草案完成，待決策
- [🟡] Step 11: 2.0 設計（Spring Boot 4.1 升級 + Repo 拆分）— 設計草案完成，待決策
- [🟢] Step 12: 建立 `1.x` 維護分支（M0；`1.1.0` 待發佈）
- [🟢] Step 13: 升級到 Spring Boot 4.1.1（M1；待合併）
- [🟡] Step 14: Authorization Server 詳細設計（資料模型 + 元件與流程）— 設計草案完成，待確認
- [🟢] Step 15: 資料庫抽象（預設 SQLite、YAML 切換 PostgreSQL）設計與實測

---

## Step 1: 建立 Maven Multi-Module 骨架
- **Status**: 🟢 Completed
- **Decision Log**:
  - **DEC-002**: 採納了更精細的模組劃分，將 `starter`, `autoconfigure`, `annotations` 分離，以提高模組的內聚性與清晰度。
  - **DEC-003**: 將根 POM artifactId 直接命名為 `jacky917-security-parent`，使其職責更明確。

---

## Step 2: 引入 Spring Boot & Security 依賴並實作基礎 AutoConfiguration
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `jacky917-security-autoconfigure` 模組引入 `spring-boot-starter-security`, `spring-boot-starter-oauth2-resource-server`, `spring-boot-starter-web` (optional)。
  - [x] `demo-resource-server` 模組引入 `spring-boot-starter-web` 與 `jacky917-security-starter`。
  - [x] 建立 `Jacky917SecurityProperties` 屬性類。
  - [x] 建立 `Jacky917SecurityAutoConfiguration`，包含預設的 `SecurityFilterChain`。
  - [x] 透過 `AutoConfiguration.imports` 註冊自動配置。
  - [x] 實作統一的 401/403 JSON 錯誤回應。
  - [x] 執行 `mvn -U -q -DskipTests package` 命令成功。
  - [x] 更新 `docs/PROJECT_STRUCTURE.md` 檔案。
- **Commands Run & Results**:
  - `mvn -U -q -DskipTests package`: **SUCCESS** (第二次，第一次因缺少依賴而失敗)
- **Files Changed**:
  - **Updated**: `jacky917-security-autoconfigure/pom.xml`
  - **Updated**: `demo-resource-server/pom.xml`
  - **New**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/properties/Jacky917SecurityProperties.java`
  - **New**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/config/Jacky917SecurityAutoConfiguration.java`
  - **New**: `jacky917-security-autoconfigure/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-004**: 在 `autoconfigure` 模組中將 `spring-boot-starter-web` 依賴設定為 `<optional>true</optional>`，因為統一錯誤處理需要用到 `HttpServletResponse` 等類，但又不希望強制非 Web 環境的使用者引入 Web 依賴。
- **Next TODO**:
  - 執行 Step 3，實作 JWT Claims 到 Spring Security `GrantedAuthority` 的複雜映射邏輯。

---

## Step 3: 實作 JWT Claims 權限映射
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 完成 `JwtAuthoritiesExtractor`，支援 `roles` / `permissions` / `scope` / `scp` 合併映射。
  - [x] 支援 claim 名稱與前綴覆寫（`jacky917.security.jwt.claims.*`、`jacky917.security.jwt.prefix.*`）。
  - [x] 支援多種輸入型態（List、逗號字串、空白分隔字串）。
  - [x] Authorities 合併後去重且穩定排序。
  - [x] `debugLog=true` 僅輸出 authorities，不輸出 token 全文。
  - [x] 已接入 `JwtAuthenticationConverter` 流程，`@PreAuthorize` 可直接使用。
  - [x] 單元測試覆蓋輸入型態、覆寫、空值/缺欄位/格式錯誤。
  - [x] `mvn -U clean verify` 成功。
  - [x] 更新 `docs/jwt-claims.md` 與 `docs/starter-design.md`。
  - [x] 更新 `docs/PROJECT_STRUCTURE.md`。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**
- **Files Changed**:
  - **Updated**: `jacky917-security-autoconfigure/pom.xml`
  - **Updated**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/config/Jacky917SecurityAutoConfiguration.java`
  - **Updated**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/properties/Jacky917SecurityProperties.java`
  - **Updated**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/authentication/JwtAuthoritiesExtractor.java`
  - **Updated**: `jacky917-security-autoconfigure/src/test/java/jacky917/security/autoconfigure/authentication/JwtAuthoritiesExtractorTest.java`
  - **Deleted**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/jwt/JwtAuthoritiesExtractor.java`
  - **Deleted**: `jacky917-security-autoconfigure/src/test/java/jacky917/security/autoconfigure/jwt/JwtAuthoritiesExtractorTest.java`
  - **Updated**: `docs/jwt-claims.md`
  - **Updated**: `docs/starter-design.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-005**: `permissions` 預設前綴改為 `PERM_`，與 `ROLE_`、`SCOPE_` 形成一致命名規範，降低授權規則混淆風險。
  - **DEC-006**: `JwtAuthoritiesExtractor` 對非預期 claim 型態採忽略策略，避免因異常 token 格式導致整體驗證流程中斷。
  - **DEC-007**: 移除重複的 extractor 與重複測試來源，統一單一路徑，確保建置與測試可重現。
- **Expected Artifacts**:
  - `JwtAuthoritiesExtractor.java`
  - 更新後的 `Jacky917SecurityAutoConfiguration.java`
- **Next TODO**:
  - 執行 Step 4：建立自訂授權註解（`@RequireRole/@RequirePerm/@RequireAny/@RequireAll`）並補整合測試。

---
## Step 4: 自訂註解（裝飾器）+ 方法級授權測試
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 在 `jacky917-security-annotations` 提供 `@RequireRole`、`@RequirePerm`、`@RequireAny`、`@RequireAll`、`@RequireScope`。
  - [x] 註解使用 `@PreAuthorize` meta-annotation。
  - [x] 方法級安全可由 `jacky917.security.method-security.enabled` 控制。
  - [x] 以 `Spring Boot Test + MockMvc` 驗證 AND/OR 的 200/403 行為。
  - [x] 更新 `docs/authorization-model.md`，補齊 A/B/C/D 註解示例。
  - [x] 執行 `mvn -U clean verify` 成功。
  - [x] 更新 `docs/PROJECT_STRUCTURE.md`。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**
- **Files Changed**:
  - **Updated**: `jacky917-security-annotations/pom.xml`
  - **New**: `jacky917-security-annotations/src/main/java/jacky917/security/annotations/RequireRole.java`
  - **New**: `jacky917-security-annotations/src/main/java/jacky917/security/annotations/RequirePerm.java`
  - **New**: `jacky917-security-annotations/src/main/java/jacky917/security/annotations/RequireAny.java`
  - **New**: `jacky917-security-annotations/src/main/java/jacky917/security/annotations/RequireAll.java`
  - **New**: `jacky917-security-annotations/src/main/java/jacky917/security/annotations/RequireScope.java`
  - **Updated**: `jacky917-security-autoconfigure/pom.xml`
  - **Updated**: `jacky917-security-autoconfigure/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
  - **Updated**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/config/Jacky917SecurityAutoConfiguration.java`
  - **New**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/methodsecurity/Jacky917AuthorityEvaluator.java`
  - **New**: `jacky917-security-autoconfigure/src/test/java/jacky917/security/autoconfigure/integration/MethodSecurityAnnotationsIntegrationTest.java`
  - **Updated**: `docs/authorization-model.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-008**: `@RequireAny/@RequireAll` 採用 `|` 分隔單一字串格式（例如 `ROLE_ADMIN|PERM_order:read`），避免 SpEL 模板對陣列參數展開造成解析錯誤。
  - **DEC-009**: 新增 `jacky917AuthorityEvaluator` Bean 專責處理 OR/AND 判斷，讓註解保持精簡且可測試。
  - **DEC-010**: 將 `@EnableMethodSecurity` 移至條件化內部配置，確保可透過 `jacky917.security.method-security.enabled` 關閉。
- **Expected Artifacts**:
  - `RequireRole.java`
  - `RequirePerm.java`
  - `RequireAny.java`
  - `RequireAll.java`
  - `MethodSecurityAnnotationsIntegrationTest.java`
- **Next TODO**:
  - 執行 Step 5：補齊更多安全情境整合測試（含 401/403 JSON body 驗證），並開始 `demo-resource-server` 的實際端點示範。

---
## Step 5: demo-resource-server（可跑、可 curl、可測）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `demo-resource-server` 提供完整端點：`/public/ping`、`/secure/me`、`/secure/role-a`、`/secure/perm-bb`、`/secure/and`、`/secure/or`、`/secure/abac/{clipId}`。
  - [x] 提供本地測試 JWT 工具（JWK + Java CLI）。
  - [x] 提供 ABAC hook 介面與預設拒絕實作，並在 demo 加上可通過規則。
  - [x] MockMvc 整合測試覆蓋 401/403/200、AND/OR、JSON 錯誤欄位。
  - [x] `mvn -U clean verify` 成功。
  - [x] `mvn -pl demo-resource-server -U spring-boot:run` 可啟動（啟動前需先 `mvn -U -DskipTests install` 讓本地 SNAPSHOT 可被解析）。
  - [x] 更新 `README.md` 與 `docs/PROJECT_STRUCTURE.md`。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**
  - `mvn -pl demo-resource-server -U spring-boot:run`: **SUCCESS**（確認啟動成功）
  - `mvn -U -DskipTests install`: **SUCCESS**（支援單模組 `spring-boot:run` 解析本地 SNAPSHOT）
- **Files Changed**:
  - **Updated**: `demo-resource-server/pom.xml`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/DemoResourceServerApplication.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/config/DemoJwtDecoderConfiguration.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/controller/DemoSecureController.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/authz/AuthzService.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/authz/DenyAllAuthzService.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/authz/DemoAuthzConfiguration.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/tools/GenerateTestJwtMain.java`
  - **New**: `demo-resource-server/src/main/resources/application.yml`
  - **New**: `demo-resource-server/src/main/resources/demo/jwk/demo-hs256.jwk.json`
  - **New**: `demo-resource-server/src/test/java/jacky917/demo/resourceserver/DemoResourceServerIntegrationTest.java`
  - **Updated**: `README.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-011**: Demo JWT 採用對稱式 JWK（HS256）以降低本地測試門檻，並由 CLI 與 Resource Server 共用同一測試金鑰。
  - **DEC-012**: ABAC 端點使用單一 `@PreAuthorize` 組合 RBAC+ABAC 條件，避免與 meta-annotation 產生雙 `@PreAuthorize` 衝突。
  - **DEC-013**: 為符合使用者指定啟動命令，先加入 `mvn -U -DskipTests install` 流程，確保單模組啟動可解析本地 SNAPSHOT 依賴。
- **Expected Artifacts**:
  - `DemoSecureController.java`
  - `GenerateTestJwtMain.java`
  - `DemoResourceServerIntegrationTest.java`
- **Next TODO**:
  - 執行 Step 6：補齊 `demo-authorization-server`（簽發 JWT）與完整手動 E2E 測試文件。

---
## Step 6: 實作 Demo Auth Server 與 E2E 測試流程
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 建立 `demo-authorization-server` 模組，並引入 `spring-boot-starter-web` 等必要依賴。
  - [x] 實作 `/oauth2/token` 端點，能讀取共用的 JWK 金鑰並簽發包含 `sub`, `roles`, `permissions`, `scp`, `sid` 的 JWT。
  - [x] 新增 `docs/e2e-testing.md`，提供完整的手動 E2E 測試指南（包含啟動兩個 demo 服務與 curl 指令）。
  - [x] 更新 `README.md`，加入 E2E 執行範例。
  - [x] 執行 `mvn -U clean verify` 成功。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**
  - `mvn -pl demo-authorization-server -U spring-boot:run`: **SUCCESS**（服務可於 `8081` 啟動）
  - `curl -X POST http://localhost:8081/oauth2/token ...`: **SUCCESS**（成功取得 `Bearer` JWT）
- **Files Changed**:
  - **Updated**: `demo-authorization-server/pom.xml`
  - **New**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/DemoAuthorizationServerApplication.java`
  - **New**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/controller/AuthController.java`
  - **New**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/controller/TokenRequest.java`
  - **New**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/controller/TokenResponse.java`
  - **New**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/service/JwtIssuerService.java`
  - **New**: `demo-authorization-server/src/main/resources/application.yml`
  - **New**: `demo-authorization-server/src/main/resources/demo/jwk/demo-hs256.jwk.json`
  - **New**: `demo-authorization-server/src/test/java/jacky917/demo/authorizationserver/AuthControllerIntegrationTest.java`
  - **New**: `docs/e2e-testing.md`
  - **Updated**: `README.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-014**: Auth Server 採用最小化 mock 登入流程（固定密碼 `password`）以降低 E2E 測試啟動成本，避免引入非必要認證複雜度。
  - **DEC-015**: 為避免跨模組檔案依賴耦合，`demo-authorization-server` 複製同一份測試 JWK 到本模組 resources，確保可獨立啟動。
  - **DEC-016**: Token claim 以 `roles/permissions/scp/sid` 為主，維持與 resource-server 權限抽取器契約一致，確保 E2E 可重現。
- **Expected Artifacts**:
  - `AuthController.java`
  - `JwtIssuerService.java`
  - `AuthControllerIntegrationTest.java`
  - `docs/e2e-testing.md`
- **Next TODO**:
  - 執行 Step 7：補齊 Refresh Token Rotation 設計與資料表 Schema（`docs/database-schema.md`、`docs/refresh-rotation.md` 最終校準）。

---
## Step 7: 補齊 Refresh Token Rotation 設計與資料表 Schema
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 更新 `docs/database-schema.md`，包含 `auth_session`, `refresh_token` 等表結構的 DDL 與索引建議。
  - [x] 更新 `docs/refresh-rotation.md`，說明 10 分鐘短效 Access Token 搭配 Rotation、Reuse Detection (重用偵測) 與 sid 裝置踢除邏輯。
  - [x] 執行 `mvn -U clean verify` 成功。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**
  - `tree -a -I 'target|.git'`: **SUCCESS**（結構掃描完成）
- **Files Changed**:
  - **Updated**: `docs/database-schema.md`
  - **Updated**: `docs/refresh-rotation.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-017**: 資料表命名統一為 `auth_session` / `refresh_token`，明確表達 Authorization Server 責任邊界，避免與 Resource Server 邏輯混淆。
  - **DEC-018**: Refresh Token 設計採 `family_id` 家族撤銷策略，於重用偵測時可快速封鎖整條輪換鏈。
  - **DEC-019**: 單裝置踢除以 `sid`（session 維度）處理，避免傳統全域版本號策略造成多裝置互踢。
- **Expected Artifacts**:
  - `docs/database-schema.md`
  - `docs/refresh-rotation.md`
  - 更新後的 `docs/PROGRESS.md`（宣告完成）
  - 更新後的 `docs/PROJECT_STRUCTURE.md`
- **Next TODO**:
  - 執行 Step 8：引入 Swagger UI 與 MySQL 資料庫，改為資料庫導向 ABAC 示範。

---
## Step 8: 引入 Swagger UI 與 MySQL 資料庫情境
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 在 `demo-resource-server` 與 `demo-authorization-server` 引入 Swagger UI（OpenAPI 3）。
  - [x] Starter 預設放行 Swagger 相關路徑（`/swagger-ui/**`, `/v3/api-docs/**` 等）。
  - [x] `demo-resource-server` 僅在 demo 模組加入 JPA + MySQL，Starter 保持無狀態且不依賴資料庫。
  - [x] 建立 `Clip` 實體與 `ClipRepository`，ABAC 改為查 DB 比對 `ownerId` 與 JWT `sub`。
  - [x] 測試環境以 H2 驗證，`mvn -U clean verify` 成功。
  - [x] 更新 `README.md`、`docs/PROJECT_STRUCTURE.md`。
  - [x] 成功發佈 GitHub Packages 並完善 `README.md` 依賴下載與 PAT 驗證說明。
- **Commands Run & Results**:
  - `mvn -U clean verify`: **SUCCESS**（第二次，第一次修正測試設定後通過）
  - `tree -a -I 'target|.git'`: **SUCCESS**
- **Files Changed**:
  - **Updated**: `demo-resource-server/pom.xml`
  - **Updated**: `demo-authorization-server/pom.xml`
  - **Updated**: `jacky917-security-autoconfigure/src/main/java/jacky917/security/autoconfigure/properties/Jacky917SecurityProperties.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/clip/Clip.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/clip/ClipDemoDataInitializer.java`
  - **New**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/clip/ClipRepository.java`
  - **Updated**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/authz/DemoAuthzConfiguration.java`
  - **Updated**: `demo-resource-server/src/main/java/jacky917/demo/resourceserver/controller/DemoSecureController.java`
  - **Updated**: `demo-authorization-server/src/main/java/jacky917/demo/authorizationserver/controller/AuthController.java`
  - **Updated**: `demo-resource-server/src/main/resources/application.yml`
  - **New**: `demo-resource-server/src/test/resources/application.yml`
  - **Updated**: `demo-resource-server/src/test/java/jacky917/demo/resourceserver/DemoResourceServerIntegrationTest.java`
  - **Updated**: `README.md`
  - **Updated**: `docs/github-packages.md`
  - **Updated**: `docs/PROGRESS.md`
  - **Updated**: `docs/PROJECT_STRUCTURE.md`
- **Decision Log**:
  - **DEC-020**: 將所有模組的 groupId 統一修改為 com.github.jacky917，並移除子模組的自訂 version 標籤以繼承父版本，確保符合 GitHub Packages 發佈規範。
  - **DEC-021**: Demo 模組保持本地 Multi-Module 依賴，不改用 GitHub Packages 上已發佈的版本，以確保開源專案的開箱即用性 (Out-of-the-box) 並降低貢獻門檻。
  - **DEC-022**: Database 依賴僅放在 `demo-resource-server`，確保 Starter 維持 Stateless 與 DB 無關。
  - **DEC-023**: ABAC 改為資料庫 owner 比對（`clip.ownerId == JWT sub`），比寫死規則更貼近真實業務。
  - **DEC-024**: 為避免 CI 依賴外部 MySQL，測試改用 H2（`MODE=MySQL`）並在 test `application.yml` 覆蓋資料源。
  - **DEC-025**: 補上 OpenAPI 註解與 Swagger 路徑放行，確保兩個 demo 服務可直接透過 UI 驗證 API。
- **Expected Artifacts**:
  - `Clip.java`
  - `ClipRepository.java`
  - 更新後的 `DemoAuthzConfiguration.java`
  - 更新後的 `README.md`
- **Next TODO**:
  - 依實際需求擴充 Step 9（若需要：導入 Flyway、正式 migration 與 MySQL docker compose）。

---
## Step 9: 程式碼審查、Bug 修正、雙語 JavaDoc 與完整使用文件
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 全專案掃描並修正已確認的 Bug（見 Decision Log）。
  - [x] 所有 main 原始碼補上中英雙語 JavaDoc。
  - [x] 新增使用指南、設定參考、限制與注意事項、疑難排解文件。
  - [x] 修正既有文件中與程式碼不符的內容（類別名稱、Bean 名稱、MySQL 設定、ABAC 規則、錯誤的註解疊加範例）。
  - [x] 限制文件中的關鍵行為以整合測試驗證（`SecurityBehaviorIntegrationTest`）。
  - [x] `mvn clean verify` 成功。
  - [x] 更新 `docs/PROJECT_STRUCTURE.md`。
- **Commands Run & Results**:
  - `mvn -o verify`（JDK 23）：修正前 **FAILURE**（Lombok 未執行，編譯失敗）；修正後 **SUCCESS**，37 個測試全數通過。
  - `JAVA_HOME=<JDK 21> mvn -o verify`：修正前 **SUCCESS**（基準線，25 個測試）。
  - `javac -Xdoclint:all,-missing`（main 原始碼）：無 JavaDoc 錯誤。
  - `tree -a -I 'target|.git|.idea|.cursor'`：**SUCCESS**
- **Files Changed**:
  - **Updated**: `pom.xml`
  - **Updated**: `.github/workflows/publish.yml`
  - **Updated**: `jacky917-security-autoconfigure/.../config/Jacky917SecurityAutoConfiguration.java`
  - **Updated**: `jacky917-security-autoconfigure/.../methodsecurity/Jacky917AuthorityEvaluator.java`
  - **Updated**: `jacky917-security-autoconfigure/.../authentication/JwtAuthoritiesExtractor.java`
  - **Updated**: `jacky917-security-autoconfigure/.../properties/Jacky917SecurityProperties.java`
  - **Updated**: `jacky917-security-annotations/.../Require*.java`（5 個）
  - **Updated**: `demo-authorization-server`、`demo-resource-server` 所有 main 原始碼（僅 JavaDoc）
  - **Updated**: `jacky917-security-autoconfigure/src/test/.../JwtAuthoritiesExtractorTest.java`
  - **New**: `jacky917-security-autoconfigure/src/test/.../methodsecurity/Jacky917AuthorityEvaluatorTest.java`
  - **New**: `jacky917-security-autoconfigure/src/test/.../integration/SecurityBehaviorIntegrationTest.java`
  - **New**: `docs/getting-started.md`、`docs/configuration.md`、`docs/limitations.md`、`docs/troubleshooting.md`
  - **Updated**: `README.md`、`docs/starter-design.md`、`docs/authorization-model.md`、`docs/jwt-claims.md`、`docs/e2e-testing.md`、`docs/github-packages.md`、`docs/PROJECT_STRUCTURE.md`、`docs/PROGRESS.md`
- **Decision Log**:
  - **DEC-026**: `@RequireAll` / `@RequireAny` 參數解析後為空（如 `"|"`）時一律拒絕。原實作 `allMatch` 對空集合回傳 `true`，造成 fail-open。
  - **DEC-027**: 401 entry point 同時設定在 `oauth2ResourceServer` 與 `exceptionHandling`。原實作只設定後者，Token 無效／過期時回傳空 body，與「未帶 Token」的 JSON 格式不一致；並保留 RFC 6750 `WWW-Authenticate` 標頭。
  - **DEC-028**: 自動配置明確宣告於 `SecurityAutoConfiguration`、`OAuth2ResourceServerAutoConfiguration` 之前執行，並限定 Servlet Web 應用；原本僅依類別名稱字母順序剛好排在前面。
  - **DEC-029**: `AnnotationTemplateExpressionDefaults` Bean 改為 `static`，依 Spring Security 建議確保早於方法級授權攔截器建立。
  - **DEC-030**: 根 POM 明確宣告 `annotationProcessorPaths`（Lombok、configuration-processor），修正 JDK 23+ 不自動執行 annotation processor 導致的編譯失敗。
  - **DEC-031**: 發佈流程改為以 `-pl` 只部署 starter 相關模組時，必須包含根 parent POM（`-pl .,...`），否則消費端無法解析 `jacky917-security-parent`。（先前已發佈的版本使用根目錄 `mvn deploy`，已包含 parent。）
  - **DEC-032**: JavaDoc 採中英雙語（英文在前、繁體中文在後），為使用者明確要求，優先於規範中「一律繁體中文」的註解要求；README 與 docs 仍維持繁體中文。
  - **DEC-033**: 「限制與注意事項」中的行為（註解疊加 500、類別／方法註解不合併、放行路徑帶無效 Token 回 401、Boot converter 屬性被忽略、缺少 JwtDecoder 啟動失敗）皆先以測試實際驗證後才寫入文件。
- **Next TODO**:
  - 將 parent 的 `spring-boot-starter-parent` 由 `3.5.10-SNAPSHOT` 改為正式版並重新發佈（消費端目前需能存取 Spring Snapshot repository）。
  - 評估讓 `@RequireRole` / `@RequirePerm` / `@RequireScope` 的前綴跟隨 `jacky917.security.jwt.prefix.*` 設定。
  - Demo Resource Server 的 `JwtDecoder` 補上 `aud` 驗證，作為正確示範。
  - 評估錯誤回應訊息是否需要支援 i18n 或自訂。
  - 依實際需求擴充（Flyway、正式 migration、MySQL docker compose）。

---
## Step 10: Authorization Server 設計（方案 C，支援第三方登入）
- **Status**: 🟡 設計草案完成，等待決策（尚未實作）
- **背景**：比較 A（外部 IdP）、B（自建登入 API）、C（標準 OAuth 2.0／OIDC）、D（權限中心）四個方案後，決定採用 C，以支援第三方登入（Google 等）。
- **Acceptance Criteria**:
  - [x] 撰寫 `docs/auth-server-design.md`：架構、14 項決策（含選項比較與推薦）、模組結構、完整 DDL、Token claim 契約、流程圖、端點、設定與擴充點、安全檢查清單、分階段計畫。
  - [x] 查證影響決策的外部事實：Spring Boot 3.5 開源支援已於 2026-06-30 結束；SAS 1.5.x 為最後獨立版本並併入 Spring Security 7；SAS 不發 Refresh Token 給 public client；SAS 預設 `aud` 為 client_id。
  - [x] 更新 `README.md` 文件導覽、`docs/PROJECT_STRUCTURE.md`；在 `database-schema.md`、`refresh-rotation.md` 標註已由新設計取代。
  - [ ] 使用者確認 `docs/auth-server-design.md` §12 的待確認事項。
- **Commands Run & Results**:
  - 文件連結與錨點檢查：無錯誤。
  - `mvn -o clean verify`：**SUCCESS**，37 個測試全數通過（僅文件變更，程式碼未修改）。
- **Files Changed**:
  - **New**: `docs/auth-server-design.md`
  - **Updated**: `README.md`、`docs/database-schema.md`、`docs/refresh-rotation.md`、`docs/PROJECT_STRUCTURE.md`、`docs/PROGRESS.md`
- **Decision Log**:
  - **DEC-034**: 登入服務採方案 C（Spring Authorization Server，標準 OAuth 2.0／OIDC），以支援第三方登入與未來的第三方應用接入。
  - **DEC-035**: AS 以獨立 starter（`jacky917-auth-server-starter`）交付，僅供建置單一獨立部署的登入服務；業務 API 不得引入。
  - **DEC-036**（待確認）：建議先將整個 repo 升級至 Spring Boot 4／Spring Security 7，需修改「Spring Boot 3.5.10」硬性決策。
- **Next TODO**:
  - 取得 §12 待確認事項的答覆（Boot 版本、第三方登入提供者、資料庫、BFF、行動 App、註冊範圍、既有使用者匯入、網域規劃）。
  - 依答覆定稿設計，開始第 0 階段。

---
## Step 11: 2.0 設計（Spring Boot 4.1 升級 + Repo 拆分）
- **Status**: 🟡 設計草案完成，等待決策（尚未實作）
- **背景**：使用者決定兩大任務：① 升級到 Spring Boot 4.1；② 實作方案 C（Authorization Server）。先撰寫設計書與 repo 拆分方案。
- **Acceptance Criteria**:
  - [x] `docs/v2-overview.md`：目標、執行順序（M0～M6）、2.0 破壞性變更清單、決策索引、風險、依里程碑排序的待確認事項。
  - [x] `docs/boot4-migration-design.md`：版本對照、逐檔影響清單、`beforeName` 與 Jackson 3 做法、路徑比對變化、步驟、回歸檢查、風險。
  - [x] `docs/repo-structure-design.md`：4 種拆分方案比較、目標結構、依賴方向規則（enforcer）、flatten／BOM、命名（artifactId、套件、屬性、groupId、repo 名稱）、版本與分支、CI、重構步驟、R-D1～R-D10。
  - [x] `docs/auth-server-design.md`：D01 標示為已決定（Boot 4.1.1）；模組名稱、屬性前綴、BFF 實作、JDBC schema 注意事項依查證結果更新。
  - [x] 查證（Maven Central，2026-10-07）：Boot 4.1.1 的 starter 新名稱與舊名稱棄用描述；`SecurityAutoConfiguration`、`OAuth2ResourceServerAutoConfiguration`、`AutoConfigureMockMvc` 的新套件；Boot 4.1.1 管理的版本（Security 7.1.1、Framework 7.0.9、Jackson 3.1.5、Hibernate 7.4.5、JUnit 6.0.3）；Security 7.1.1 仍有 `AnnotationTemplateExpressionDefaults`、`JwtAuthenticationConverter`、`BearerTokenAuthenticationEntryPoint`，已移除 `AntPathRequestMatcher`、`MvcRequestMatcher`；springdoc 3.1.1；Spring Cloud 2026.0 僅有 M1。
  - [ ] 使用者確認 `docs/v2-overview.md` §7 的待確認事項。
- **Commands Run & Results**:
  - 文件連結與錨點檢查：無錯誤。
  - `mvn -o clean verify`：**SUCCESS**（僅文件變更，程式碼未修改）。
- **Files Changed**:
  - **New**: `docs/v2-overview.md`、`docs/boot4-migration-design.md`、`docs/repo-structure-design.md`
  - **Updated**: `docs/auth-server-design.md`、`README.md`、`docs/PROJECT_STRUCTURE.md`、`docs/PROGRESS.md`
- **Decision Log**:
  - **DEC-037**: 平台升級至 Spring Boot 4.1.1（使用者決定）。取代原硬性決策「Spring Boot 3.5.10」；`.cursor/rules` 中的硬性決策需同步更新。DEC-036 結案。
  - **DEC-038**（建議，待確認）：執行順序為 M0 切 `1.x` → M1 升級（結構不變）→ M2 重構 → M3 發佈 2.0.0 → M4～M6 AS（2.1～2.3）。先升級再重構，讓問題可以分開定位。
  - **DEC-039**（建議，待確認）：單一 repo、多模組、統一版本；以 enforcer 禁止 Resource Server 模組依賴 Authorization Server 模組。
- **Next TODO**:
  - 取得 `docs/v2-overview.md` §7 的答覆，優先處理 M0 前需要決定的兩項（commit 目前變更、1.x 維護期）。

---
## Step 12: 建立 `1.x` 維護分支（M0）
- **Status**: 🟢 Completed（尚未發佈）
- 詳細紀錄見 `1.x` 分支的 `docs/PROGRESS.md`：parent 改為 `3.5.16`、版本 `1.1.0`、37 個測試通過。

---
## Step 13: 升級到 Spring Boot 4.1.1（M1）
- **Status**: 🟢 Completed（分支 `claude/spring-boot-4.1-upgrade`，待合併）
- **Acceptance Criteria**:
  - [x] parent `3.5.10-SNAPSHOT` → `4.1.1`，版本 `2.0.0-SNAPSHOT`，移除 Spring Snapshot repository。
  - [x] Starter 改用新名稱：`spring-boot-starter-webmvc`、`spring-boot-starter-security-oauth2-resource-server`；測試改用 `spring-boot-starter-security-test`、`spring-boot-starter-webmvc-test`。
  - [x] 自動配置改用 `beforeName`（Boot 4 的新類別位置），新增 `AutoConfigurationOrderingIntegrationTest` 鎖住排序。
  - [x] 錯誤回應改用應用程式的 Jackson 3 `JsonMapper`，新增 `ErrorResponseJsonMapperIntegrationTest`。
  - [x] `@AutoConfigureMockMvc` 改為 `org.springframework.boot.webmvc.test.autoconfigure`。
  - [x] Demo 移除 Jackson 2（JWK 直接以字串交給 Nimbus 解析）；springdoc `3.1.1`；`exec-maven-plugin` 明確指定 `3.6.4`。
  - [x] 手動 E2E：兩個 demo 以 Boot 4.1.1 啟動，14 個請求結果符合預期（Resource Server 以 H2 執行）。
  - [x] 文件更新：相容性、版本線、依賴名稱、`WWW-Authenticate`、`FACTOR_BEARER`、路徑樣式規則、Jackson 行為。
- **Commands Run & Results**:
  - `mvn -B clean verify`：第一次 **FAILURE**（2 個測試：`WWW-Authenticate` 多了 `resource_metadata`；authority 多了 `FACTOR_BEARER`），確認為 Spring Security 7 的預期行為後調整測試；之後 **SUCCESS**，41 個測試全數通過。
  - `mvn -B -q validate`：修正 `exec-maven-plugin` 版本警告後無警告。
  - 路徑樣式探測：`/api/**/admin`、`/files/**/*.png` 啟動失敗（`PatternParseException`），`/public/**` 正常。
- **Decision Log**:
  - **DEC-041**: 錯誤回應採用 `ObjectProvider<JsonMapper>.getIfUnique`，有多個 `JsonMapper` 時退回預設 mapper，避免因 bean 不唯一而失敗。
  - **DEC-042**: 接受 Spring Security 7 新增的 `FACTOR_BEARER` authority 與 RFC 9728 `resource_metadata`，不加以移除；於文件中說明。
- **Next TODO**:
  - 在有 Docker 的環境驗證 MySQL（Connector/J 9.7.0）。
  - PR #1 合併後，將本分支以 PR 合併到 `main`，並發佈 `2.0.0-M1`。

---
## Step 14: Authorization Server 詳細設計（方案 C）
- **Status**: 🟡 設計草案完成，待確認（尚未實作）
- **Acceptance Criteria**:
  - [x] `docs/auth-server-data-model.md`：23 張表的完整 DDL（官方表依 jar 內 schema 檔改為 PostgreSQL 版）、欄位說明、索引與理由、狀態機、關鍵查詢、初始資料、Flyway 規劃、DB 帳號權限、清理規則與容量估算。
  - [x] `docs/auth-server-detailed-design.md`：D15～D21、套件與元件、與 Spring Security AS 的整合點、SPI、三條 filter chain、Token 有效期與 claim 規則、六個主要流程（含失敗分支）、設定屬性規格、錯誤處理、稽核與 metrics、威脅模型、37 個測試案例、第 1～2 階段工作分解。
  - [x] `docs/auth-server-design.md`：§5 改為摘要並指向資料模型；`sid` → `asid`；移除表名前綴；新增 D15～D21 索引。
- **查證（Spring Security 7.1.1、Spring Session 4.1.1 jar）**:
  - 官方 schema 檔內容與 PostgreSQL 調整說明（`blob`→`text`、`timestamp`→`timestamptz`）；官方表沒有任何索引。
  - `JdbcOAuth2AuthorizationService` 表名為寫死常數 `TABLE_NAME = "oauth2_authorization"` → 取消表名前綴（D17）。
  - `TokenSettings` 預設：授權碼與 Access Token 5 分鐘、Refresh Token 60 分鐘、`reuseRefreshTokens=true`。
  - `OAuth2RefreshTokenGenerator` 不發 Refresh Token 給授權碼流程的 public client；刷新流程支援 DPoP。
  - `JwtGenerator` 由 `SessionInformation` 產生 ID Token 的 `sid`，`OidcLogoutAuthenticationProvider` 以 `SessionRegistry` 驗證 → Access Token 改用 `asid`（D20）。
  - Jackson 3 內建 `UserMixin`、`UsernamePasswordAuthenticationTokenMixin` → Principal 標準化不需自訂 mixin（D16）。
  - `HttpSecurity#oauth2AuthorizationServer`、`OAuth2AuthorizationServerConfigurer`（僅公開建構子）、`tokenEndpoint().authenticationProviders(...)`、`OidcLogoutAuthenticationSuccessHandler#setLogoutHandler`、Pushed Authorization Request configurer 皆存在。
- **Commands Run & Results**:
  - 以 embedded PostgreSQL 16.15 執行資料模型全部 DDL，並以 Spring Security 7.1.1 官方 JDBC 類別存取：**40 項檢查全部通過**（見 `docs/auth-server-data-model.md` §16）。第一次執行時有 1 項約束測試的 SQL 本身寫錯，修正後才確認該約束確實生效。
  - 文件連結、錨點與 YAML 檢查：無錯誤。
- **Decision Log**:
  - **DEC-043**: 表設計以 `docs/auth-server-data-model.md` 為唯一權威來源，避免兩份 DDL 逐漸不一致。
  - **DEC-044**: AS 使用專屬資料庫並取消表名前綴（D17）。
  - **DEC-045**: Access Token 以 `asid` 表示登入 Session（D20）。
  - **DEC-046**: Refresh 以列鎖序列化，並設 30 秒寬限期區分併發與重用攻擊（D19）。
- **Next TODO**:
  - 取得 `docs/auth-server-detailed-design.md` §12 的答覆。
  - 完成 M2（repo 重構）後，依詳細設計 §11 開始第 1 階段。

---
## Step 15: 資料庫抽象（預設 SQLite、YAML 切換 PostgreSQL）
- **Status**: 🟢 設計完成（尚未實作）
- **使用者決定**：資料庫預設 SQLite，需抽象化以便在 YAML 無痛切換；允許以 Email 登入。
- **Acceptance Criteria**:
  - [x] 詳細設計新增 D22：可攜 SQL + 依資料庫分開的 Flyway migration（`{vendor}`）+ 極小的 `AuthorizationServerDialect`；預設 SQLite 的實作細節（`EnvironmentPostProcessor`、啟動檢查）；支援矩陣（SQLite、PostgreSQL；MySQL 第 5 階段）。
  - [x] 資料模型改為可攜：ID `VARCHAR(36)`、IP `VARCHAR(45)`、JSON `TEXT`；時間由應用程式寫入；格式驗證移到應用程式；查詢改為兩種資料庫通用的 SQL。
  - [x] 資料模型新增 §17：SQLite 型別對應、必要連線參數、限制、完整 DDL。
  - [x] D14 標示為已決定；D10、D19 補上 SQLite 的對應做法；待確認事項更新（資料庫、Email 登入已決定）。
- **Commands Run & Results**:
  - 查證：Spring Session 4.1.1 隨附 `schema-sqlite.sql`；Flyway 12.4.0 核心已內建 SQLite；Boot 4.1.1 的 `DatabaseDriver` 含 `SQLITE`，Flyway 自動配置支援 `{vendor}`。
  - SQLite 3.53.4（xerial 3.53.4.0 + HikariCP + Flyway 12.4.0）：**23 項全部通過**。過程中發現並記錄：`SQLiteDataSource` 不會套用 URL 中的 `transaction_mode`；xerial 在 `IMMEDIATE` 模式下 commit 後會立刻開始新交易並持有寫入鎖（連線池必須維持 `auto-commit=true`）；未設定 `foreign_keys=true` 時孤兒資料會被接受。
  - PostgreSQL 16.15（改為可攜型別後重新驗證）：**40 項全部通過**；每一項約束測試都確認由目標約束擋下。
  - 文件連結、錨點、YAML 檢查：無錯誤。
- **Decision Log**:
  - **DEC-047**: 預設 SQLite、YAML 切換 PostgreSQL（使用者決定，D14／D22）。
  - **DEC-048**: 不使用 JPA；以可攜 SQL + 依資料庫分開的 DDL + dialect 介面實作資料庫抽象。
  - **DEC-049**: 資料表只使用可攜型別，時間一律由應用程式寫入，格式驗證在應用程式。
  - **DEC-050**: SQLite 以 `transaction_mode=IMMEDIATE` 取代 `FOR UPDATE`，並強制檢查必要連線參數。
  - **DEC-051**: 允許以已驗證的 Email 登入（使用者決定）。

---
## Step 16: 記錄使用者決策（BFF、client_credentials）
- **Status**: 🟢 Completed
- **Decision Log**:
  - **DEC-052**: 網頁前端採用 BFF（AS D03）。
  - **DEC-053**: 第 1 階段即支援 `client_credentials`（AS D15），工作分解第 8 項納入。
- **Files Changed**: `docs/auth-server-design.md`、`docs/auth-server-detailed-design.md`、`docs/v2-overview.md`、`docs/PROGRESS.md`
- **Next TODO**:
  - AS 剩餘待確認：第三方登入提供者（推薦第 1 階段只做 Google）、行動 App、第一版是否開放註冊、既有使用者匯入、網域規劃。
  - M2 前需決定：groupId、artifactId 改名、repo 改名、2.0 破壞性清理範圍。

---
## Step 17: PR #2 review 修正
- **Status**: 🟢 Completed
- **Review 結果**：8 項中 7 項屬實；第 6 項（每次錯誤回應查一次 `JsonMapper`）成本可忽略，不修改。
- **修正內容**:
  - #1 排序測試：實驗證實原測試在 `beforeName` 打錯、甚至完全移除時都會通過（Spring Boot 先依字母順序排序，`jacky917.…` 本來就在 `org.springframework.…` 之前）。新增「`beforeName` 列出的類別都存在」的測試，並實測打錯字時會失敗；測試應用程式改為只用 `@EnableAutoConfiguration`。
  - #2 README 與使用指南的依賴範例：標示 2.x 尚未發佈、目前只有 `1.0.0`。
  - #3 資料模型：全部 23 張表統一在 V1 建立，消除 §2、§13.1、§17.4 的矛盾。
  - #4 demo 測試改用 Jackson 3，不再依賴 springdoc 間接帶入的 Jackson 2。
  - #5 401 斷言：未帶 token 時 `WWW-Authenticate` 不得包含 `error=`。
  - #7 demo 讀取 JWK 改用 `Resource#getContentAsString`。
  - #8 ShedLock 一律使用；Spring Session JDBC 只在 PostgreSQL 啟用。
- **Commands Run & Results**:
  - 原排序測試的四種破壞實驗：全部 PASS（證實測不到）。新測試：名稱正確 PASS、打錯 FAIL 並指出類別、還原後 PASS。
  - `mvn -B -o clean verify`：**SUCCESS**，42 個測試全數通過。
  - 文件連結、錨點、YAML 檢查：無錯誤。


---
## Step 18: Repo 重構與 2.0 行為清理（M2）
- **Status**: 🟢 Completed
- **使用者決定**：先做 M2 再實作 AS；groupId 改為 `io.github.jacky917`；artifactId 與 repo 名稱都改（repo → `jacky917-security`）；AS 第 1 階段採推薦範圍（只做 Google、不開放註冊、不支援行動 App、不匯入使用者）。
- **Acceptance Criteria**:
  - [x] 目錄改為 `core/`、`resource-server/`、`examples/`、`relocation/`，新增 `jacky917-security-core`（無依賴的 claim 契約）與 `jacky917-security-bom`。
  - [x] 座標改為 `io.github.jacky917`；自動配置套件改為 `jacky917.security.resourceserver.autoconfigure`。
  - [x] `${revision}` + flatten-maven-plugin：發佈的 POM 不含 parent；BOM 以 bom 模式發佈並以外部專案驗證可匯入。
  - [x] 舊座標 `com.github.jacky917:jacky917-security-starter` 以 relocation POM 導向新 starter，實測 Maven 會顯示改名提示。
  - [x] maven-enforcer：Resource Server 模組不得依賴 AS 模組；core 不得有任何依賴。實測違反時建置失敗並顯示自訂訊息。
  - [x] 2.0 行為清理：單一條件註解跟隨 `jwt.prefix.*`；`permit-all-patterns` 預設只放行 `/actuator/health`；移除 `debug-log`、`method-security.enabled`；401／403 日誌改為 DEBUG。
  - [x] CI（Java 21／25 + 文件連結檢查）；發佈流程改為部署整個 reactor 並檢查 tag 與 `revision` 一致。
  - [x] 文件改為 `docs/resource-server/`、`docs/design/`、`docs/guides/`，新增升級指南 `docs/guides/upgrade-to-2.0.md`。
  - [x] GitHub repo 改名為 `jacky917-security`（使用者確認後執行），POM 的 `url`／`scm`／`distributionManagement` 與文件連結已更新。
- **Commands Run & Results**:
  - `mvn -B -o clean verify`：**SUCCESS**，51 個測試全數通過（Resource Server 42、example-resource-server 7、example-authorization-server 2）。
  - enforcer 兩條規則的破壞實驗：都會失敗並顯示訊息；還原後通過。
  - 外部專案匯入 BOM 與舊座標：依賴解析正確，舊座標顯示 relocation 提示。
  - 文件連結、錨點、YAML 檢查：無錯誤。
- **Decision Log**:
  - **DEC-054**: 根 POM 仍繼承 `spring-boot-starter-parent`，以 flatten 產生不含 parent 的發佈 POM（偏離 R-D7 原本「不繼承 Boot parent」的設計，理由見 `docs/design/repo-structure-design.md` §11）。
  - **DEC-055**: 保留 `@Secured` 支援。原計畫在 2.0 移除，但移除後既有的 `@Secured` 會變成**完全不檢查**（fail-open），風險高於維護成本。
  - **DEC-056**: 屬性預設值維持字串常值（configuration metadata 才讀得到預設值），以單元測試確保與 core 常數一致。
  - **DEC-057**: BOM 內以 `${project.version}` 表示版本，flatten 後由使用端解析，已以外部專案驗證。
  - **DEC-058**: 授權條款尚未決定。發佈的 POM 目前帶有繼承自 Spring Boot parent 的 Apache License 2.0，**正式發佈 2.0.0 前必須決定**（根 POM 有 TODO）。
- **Next TODO**:
  - 以舊的 GitHub Packages URL 實際下載 `1.0.0`（需要有 `read:packages` 的 token）。
  - 待使用者決定：授權條款、1.1.0 發佈時間、`.cursor/rules` 是否更新為 Spring Boot 4.1。
  - 依 `docs/design/auth-server-detailed-design.md` §11 開始 AS 第 1 階段。

---
## Step 19: PR #3 review 修正
- **Status**: 🟢 Completed
- **Review 結果**：10 項中 8 項修正、2 項記錄為已知限制（使用者決定全部採用推薦方案）。
- **修正內容**:
  - 發佈流程：改為先 `mvn verify` 再 `mvn deploy -DskipTests`。原本直接 `mvn deploy` 會逐模組「測試後立即部署」，範例模組的測試失敗時，函式庫已經發佈出去。
  - 發佈流程：沒有 `LICENSE` 檔或 `<licenses>` 時拒絕發佈（授權條款尚未決定）。
  - `@Require*` 所需的 Bean 移到新的 `Jacky917AuthorityEvaluatorAutoConfiguration`，沒有任何條件。`enabled=false` 或非 Servlet 應用程式自行啟用方法級授權時，註解照常運作；原本會因找不到 `jacky917AuthorityEvaluator` 而回傳 500。
  - 文件連結檢查：重複標題依 GitHub 規則加 `-1`、`-2`；支援帶標題與 `<...>` 的連結。
  - `PROGRESS.md` Step 2～9 中 12 行被批次替換改錯的歷史路徑還原。
  - 自訂前綴的負向測試補上 `@RequireScope`。
  - 超過 80 欄的 Javadoc 換行（`AuthzService` 的 `{@code @PreAuthorize(...)}` 與 `GenerateTestJwtMain` 的命令列範例無法斷行，保留）。
  - 限制文件新增 §17（新舊座標同時存在）、§18（無法只關閉 Starter 的方法級授權）；升級指南加入對應提醒與檢查項目。
- **Commands Run & Results**:
  - 新測試的破壞實驗：從 `AutoConfiguration.imports` 移除新的自動配置後，2 個註解測試失敗；還原後通過。
  - 實驗：移除 `AnnotationTemplateExpressionDefaults` Bean 後註解仍正常。查證 Spring Security 7.1.1 的 `SecurityAnnotationScanners.requireUnique(Class)` 預設即帶入 `AnnotationTemplateExpressionDefaults`，因此修正 Javadoc 與設計文件的描述（此 Bean 改為「明確宣告並可替換」）。
  - 連結檢查的實驗：`#欄位說明-1` 通過、`#欄位說明-2` 回報缺少；帶標題與 `<...>` 的失效連結都會回報。
  - 授權條款檢查：目前沒有 `LICENSE`，檢查會中止發佈（符合預期）。
  - `mvn -B -o clean verify`：**SUCCESS**，56 個測試全數通過（Resource Server 47、example-resource-server 7、example-authorization-server 2）。
  - 文件連結、錨點、YAML 檢查：無錯誤。
- **Decision Log**:
  - **DEC-059**: `@Require*` 所需的 Bean 一律註冊，不受 `jacky917.security.enabled` 與應用程式類型影響（只負責判斷，不改變安全設定）。
  - **DEC-060**: 發佈前必須完成整個 reactor 的測試，並已宣告授權條款。
  - **DEC-061**: 不為 annotations／autoconfigure 的舊座標提供 relocation，也不恢復關閉方法級授權的開關；兩者記錄為已知限制（limitations §17、§18）。
- **Files Changed**:
  - **New**: `Jacky917AuthorityEvaluatorAutoConfiguration.java`、`StarterDisabledIntegrationTest.java`
  - **Updated**: `Jacky917SecurityAutoConfiguration.java`、`AutoConfiguration.imports`、`PrefixAndDefaultsIntegrationTest.java`、`AutoConfigurationOrderingIntegrationTest.java`、`Jacky917SecurityProperties.java`、`.github/workflows/publish.yml`、`scripts/check-doc-links.py`、`pom.xml`、`docs/resource-server/{getting-started,configuration,limitations}.md`、`docs/guides/{upgrade-to-2.0,github-packages}.md`、`docs/design/starter-design.md`、`docs/PROGRESS.md`、`docs/PROJECT_STRUCTURE.md`
- **Next TODO**:
  - 決定授權條款（新增 `LICENSE` 與 `<licenses>`）後才能發佈 2.0.0。

---
## Step 20: Authorization Server 第 1 階段——工作 1、2（模組骨架、資料庫）
- **Status**: 🟢 Completed（分支 `claude/as-phase1`，以 `claude/m2-restructure` 為基礎）
- **Acceptance Criteria**:
  - [x] 新增 `authorization-server/jacky917-security-authorization-server-autoconfigure` 與 `-starter`，加入根 POM 與 BOM。
  - [x] `AuthorizationServerProperties`（`jacky917.security.authorization-server.*`）：`enabled`、`issuer`（必填，非 localhost 必須 https）、`database.*`、`token.*`；設定錯誤時啟動失敗。
  - [x] D22：`AuthorizationServerDialect`（PostgreSQL、SQLite）、依 JDBC URL 自動選擇；`DefaultSqliteEnvironmentPostProcessor` 在未設定 `spring.datasource.url` 時使用 SQLite，建立資料夾與權限 600 的檔案；SQLite 缺少必要參數或關閉自動提交時啟動失敗。
  - [x] Flyway V1：PostgreSQL 與 SQLite 各 7 個同名檔案（23 張表 + 內建資料）。
  - [x] 新增 `SqliteExceptionTranslator`：SQLite 的約束違反轉為 Spring 的 `DuplicateKeyException`／`DataIntegrityViolationException`。
- **Commands Run & Results**:
  - AS 模組 26 個測試全數通過，SQLite 與 PostgreSQL 16.15（embedded-postgres）各跑一次：migration 與內建資料、官方 `JdbcRegisteredClientRepository`／`JdbcOAuth2AuthorizationService` 相容性（不需自訂 mixin）、約束、外鍵連帶刪除、兩種資料庫的 schema 一致性（T-DB-04）、SQLite 設定檢查（T-DB-02）、預設 SQLite（T-DB-01）、屬性驗證。
  - 破壞實驗：只改 SQLite 的一個索引名稱 → 一致性測試失敗；停用例外轉換 → 約束測試失敗；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，82 個測試（Resource Server 47、Authorization Server 26、範例 9）。
  - 文件連結、錨點、YAML 檢查：無錯誤。
- **Decision Log**:
  - **DEC-062**: 實測發現 Spring 沒有 SQLite 的錯誤碼，約束違反會變成 `UncategorizedSQLException`；新增 `SqliteExceptionTranslator` 並套用到所有 `JdbcTemplate`，讓兩種資料庫丟出相同的例外。
  - **DEC-063**: PostgreSQL 測試改用 embedded-postgres（真正的 PostgreSQL 16.15），不依賴 Docker。
  - **DEC-064**: 設定屬性只加入已實作功能使用的項目，其餘隨各工作加入。
  - **DEC-065**: 第一方 client 不寫入 migration，改由工作 4 處理。
  - **DEC-066**: 兩種資料庫的約束與索引使用相同名稱，以一致性測試防止兩份 migration 逐漸不同。
- **Files Changed**: `authorization-server/**`（新增）、`pom.xml`、`jacky917-security-bom/pom.xml`、`README.md`、`docs/design/auth-server-detailed-design.md`、`docs/design/auth-server-data-model.md`、`docs/PROGRESS.md`、`docs/PROJECT_STRUCTURE.md`
- **Next TODO**:
  - 工作 3：簽章金鑰（`SigningKeyStore`、`KeyEncryptor`、`RotatingJwkSource`）。

---
## Step 21: Authorization Server 第 1 階段——工作 3（簽章金鑰）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `SigningKeyStore` SPI 與 `JdbcSigningKeyStore`；`KeyEncryptor`（AES-256-GCM，`kid` 為附加驗證資料）；`SigningKeyService`（RS256 3072 位元／ES256，快取 1 分鐘）；`RotatingJwkSource`。
  - [x] 首次啟動自動產生 `ACTIVE` 金鑰；多實例同時建立時由唯一索引擋下並改用對方的金鑰。
  - [x] 主金鑰（`keys.encryption-key`）必填、必須是 32 bytes 的 Base64；主金鑰錯誤時啟動失敗。
  - [x] JWKS 只有公鑰；簽章另以只看得到 `ACTIVE` 私鑰的 `JwtEncoder` 進行，header 自動帶 `kid`。
- **Commands Run & Results**:
  - AS 模組 39 個測試全數通過：T-KEY-01（首次啟動、密文儲存、以 JWKS 驗證）、T-KEY-03（主金鑰錯誤時啟動失敗）、重新啟動沿用金鑰、輪換期間公開 3 把但只以 `ACTIVE` 簽章、輪換後舊 token 仍可驗證、ES256；SQLite 與 PostgreSQL 各跑一次。
  - 查證：Spring Security 7.1.1 的 `NimbusJwtEncoder` 在多把 RSA 金鑰符合時拒絕簽章，因此簽章與 JWKS 必須分開。
- **Decision Log**:
  - **DEC-067**: JWKS 與簽章使用不同的金鑰來源（公鑰／`ACTIVE` 私鑰）。
  - **DEC-068**: 私鑰密文以 `kid` 綁定；主金鑰錯誤在啟動時就失敗。
- **Next TODO**:
  - 工作 4：client（JDBC repository、`client_profile`、`ClientSecretInitializer`、第一方 client）。

---
## Step 22: Authorization Server 第 1 階段——工作 4（Client）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `RegisteredClientRepository`：官方 `JdbcRegisteredClientRepository` + `ActiveClientRegisteredClientRepository`（停權的 client 不存在 → `invalid_client`）。
  - [x] 第一方 client 在設定中宣告（`clients.<client-id>.*`），每次啟動同步：一律 `requireProofKey=true`、`reuseRefreshTokens=false`、有效期取自 `token.*`、ID Token 演算法與簽章金鑰一致。
  - [x] Secret 以 `{bcrypt}` 雜湊；設定改變時更換，相同時沿用；confidential client 沒有 secret 時啟動失敗。
  - [x] 設定驗證：redirect URI（https／localhost／RFC 8252 原生 App scheme、無 fragment）、grant type 組合、public client 限制、client id 格式；第三方 client 在第 3 階段前拒絕。
- **Commands Run & Results**:
  - AS 模組 47 個測試全數通過（SQLite 與 PostgreSQL 各跑一次）。
  - 測試發現並修正 2 個問題：① 原生 App 的 `com.example.app:/callback` 被誤判為不合法（改為允許 RFC 8252 的反向網域 scheme）；② 已停權的 client 在重新啟動時被重複新增而啟動失敗（同步改用未過濾的 repository）。
- **Decision Log**:
  - **DEC-069**: 第一方 client 以設定為準，啟動時同步（取代 migration seed 與 `ClientSecretInitializer`）。
  - **DEC-070**: 第三方 client 在同意畫面完成前直接拒絕。
- **Next TODO**:
  - 工作 5：使用者（`UserAccountService`、`UserDetailsService`、密碼政策）。

---
## Step 23: Authorization Server 第 1 階段——工作 5（使用者）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `UserAccountService` SPI 與 `JdbcUserAccountService`：以帳號或已驗證的 Email 查詢（不分大小寫）、建立使用者（UUIDv7、`USER` 角色）、角色與權限（排除過期的角色）。
  - [x] `Jacky917UserDetailsService`：username 為使用者 ID（D16）；帳號不存在、沒有密碼、已刪除、未驗證的 Email 都回相同的錯誤；停用、鎖定、`locked_until` 未到期時無法登入；強度調高後登入時自動重新雜湊（D21）。
  - [x] `PasswordPolicy`（12～128 字元）、`password.min-length`；第一位管理員（`bootstrap-admin.*`）。
- **Commands Run & Results**:
  - AS 模組 58 個測試全數通過（SQLite 與 PostgreSQL 各跑一次），以 Spring Security 的 `DaoAuthenticationProvider` 實際驗證。
  - 發現：Spring Security 的錯誤訊息依 JVM 語系翻譯，測試改為比對「所有失敗的訊息相同」；Spring Security 7 會在帳號密碼登入時加入 `FACTOR_PASSWORD` authority。
- **Decision Log**:
  - **DEC-071**: `UserDetails` 的 username 直接使用使用者 ID，帳號密碼登入不需要 `PrincipalNormalizer`。
  - **DEC-072**: 帳號不可含 `@`，讓「帳號或 Email」登入不會混淆。
  - **DEC-073**: 第一位管理員在第 1 階段即提供（不開放註冊時的唯一入口）。
- **Next TODO**:
  - 工作 6：登入（filter chain、登入頁、成功／失敗處理、`auth_session`）。

---
## Step 24: Authorization Server 第 1 階段——工作 6（登入）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] Order 1 filter chain：Spring Authorization Server 端點（OIDC、`/userinfo` 以 Access Token 存取）；未登入的瀏覽器導向 `/login`。
  - [x] Order 3 filter chain：登入表單（CSRF）、登入後更換 Session ID、`X-Frame-Options: DENY`、CSP。
  - [x] 登入頁（Thymeleaf）：依請求語言顯示繁體中文或英文；所有錯誤顯示相同訊息；品牌設定（產品名稱、logo、主色）。
  - [x] `LoginSuccessHandler`：記錄登入、建立 `auth_session`（`PASSWORD`／`local`／`pwd`）、瀏覽器 Session 存放 `asid`。
  - [x] 自動配置排在 Spring Boot 的安全性與 Authorization Server 自動配置之前（以測試確認類別名稱存在）。
- **Commands Run & Results**:
  - 以 MockMvc 模擬瀏覽器與 BFF 走完授權碼 + PKCE 流程（從登入頁 HTML 取得 CSRF token），SQLite 與 PostgreSQL 各一次：Access Token 的 `sub` 為使用者 ID、帶 `kid`、有 Refresh Token 與 ID Token；另驗證無 PKCE 被拒、未註冊的 redirect 回 400、`client_credentials` 的 `sub` 為 client id、停權 client 回 `invalid_client`、discovery 的 issuer、JWKS 只有公鑰。
  - 測試發現並修正：`?error` 沒有值時，部分容器傳回 null，登入頁因此不顯示錯誤（改為判斷參數是否存在）。
  - `mvn -B -o clean verify`：**SUCCESS**，131 個測試（Resource Server 47、Authorization Server 75、範例 9）。
- **Decision Log**:
  - **DEC-074**: 登入頁使用 starter 自己的訊息檔，不依賴應用程式的 `MessageSource`。
  - **DEC-075**: 主色以 `/jacky917/theme.css` 提供，只接受色碼。
- **Next TODO**:
  - 工作 7：`SessionLinkingAuthorizationService`（授權與 `auth_session` 的連結）。

---
## Step 25: Authorization Server 第 1 階段——工作 7（授權與登入 Session 的連結）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `SessionLinkingAuthorizationService` 包裝官方 `JdbcOAuth2AuthorizationService`：授權碼流程的授權第一次儲存時，從瀏覽器 Session 取得 `asid`，在同一個交易中寫入 `session_authorization`。
  - [x] 換 Token、刷新沿用既有連結；`client_credentials` 不建立連結。
  - [x] 沒有 `asid`、或 `asid` 不是同一位使用者的 `ACTIVE` Session 時拒絕，授權一併回滾。
- **Commands Run & Results**:
  - AS 模組 79 個測試全數通過；新增：連結建立一次、刷新換發新的 Refresh Token 且舊的失效、連結不變、拒絕沒有 Session 的授權並確認沒有殘留（SQLite 與 PostgreSQL）。
  - 破壞實驗：移除交易 → 「不留下沒有連結的授權」的斷言失敗；還原後通過。
- **Decision Log**:
  - **DEC-076**: 以「連結是否已存在」決定是否需要 `asid`（換 Token 也有 HTTP 請求，原設計的判斷會誤擋）。
- **Next TODO**:
  - 工作 8：`Jacky917TokenCustomizer`（`aud`、`asid`、`idp`、`roles`、`permissions`、ID Token 的使用者資料）。

---
## Step 26: Authorization Server 第 1 階段——工作 8（Token）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] `Jacky917TokenCustomizer`：Access Token 的 `aud`（`jacky917-api`）、`client_id`、`asid`、`idp`、`roles`（只給第一方）、`permissions`；ID Token 的 `amr`、`name`／`picture`／`locale`（`profile` scope）、`email`（`email` scope 且已驗證）；ID Token 不放角色與權限。
  - [x] `client_credentials` 的 Token 只有 `aud`、`client_id`、`scope`（`sub` 為 client id）。
  - [x] 角色與權限每次簽發都從資料庫讀取（D18）；使用者無法登入或登入 Session 失效時回 `invalid_grant`。
  - [x] SPI：`AuthorityResolver`（含第三方的 scope 交集）、`AudienceResolver`、`TokenClaimsContributor`。
- **Commands Run & Results**:
  - AS 模組 87 個測試全數通過（SQLite 與 PostgreSQL 各一次）：T-TOKEN-01～05、Session 撤銷／停用／暫時鎖定後拒絕刷新、自訂 claim 經刷新後仍存在。
  - 查證：Spring Security 7.1.1 的 `JwtGenerator` 已設定 ID Token 的 `sid`、`auth_time`、`azp`、`nonce`；Access Token 的 `aud` 預設為 client id，且沒有 `client_id` claim。
  - 測試發現並修正：claim 使用 `List.of()` 等不可變集合時，授權存入資料庫後無法讀回，刷新失敗（customizer 最後統一轉為 `ArrayList`／`LinkedHashMap`）。
  - `mvn -B -o clean verify`：**SUCCESS**，143 個測試（Resource Server 47、Authorization Server 87、範例 9）。
- **Decision Log**:
  - **DEC-077**: `auth_time` 沿用 Spring Security 的值，不覆寫。
  - **DEC-078**: 第 1 階段在簽發 Token 時即檢查使用者與 Session 狀態。
  - **DEC-079**: 沒有 `client_profile` 的 client 視為第三方。
- **Next TODO**:
  - 工作 9：Google 登入（通用 OIDC mapper、`FederatedIdentityService`、自動建立使用者）。

---
## Step 27: Authorization Server 第 1 階段——工作 9（Google 登入）
- **Status**: 🟢 Completed
- **Acceptance Criteria**:
  - [x] 以 Spring Boot 標準的 `spring.security.oauth2.client.registration.*` 設定提供者；有設定時才啟用 `oauth2Login`，登入頁自動顯示「使用 Google 登入」。
  - [x] `OidcFederatedUserInfoMapper`（通用 OIDC）、`FederatedIdentityService`：已連結 → 登入（停用者拒絕）；已驗證的 Email 屬於既有帳號 → 拒絕；其餘建立新使用者（只儲存已驗證的 Email）。
  - [x] `FederatedLoginSuccessHandler`：建立 `auth_session`（`FEDERATED`／提供者／`fed`）、`PrincipalNormalizer`（D16）、移除提供者的 token。
- **Commands Run & Results**:
  - 以 JDK `HttpServer` 實作假的 Google（token、JWKS、userinfo），Spring 的 oauth2Login 實際換 code 並驗證 ID Token；SQLite 與 PostgreSQL 各 6 個測試全數通過（T-FED-01／02／04／06、Email 屬於既有帳號、登入頁按鈕）。
  - 測試發現：Spring Security 7.1.1 的 `oauth2Login` 不會加入 factor authority，`JwtGenerator` 因而無法決定 `auth_time` 而拒絕簽發 ID Token；`PrincipalNormalizer` 補上 `FACTOR_AUTHORIZATION_CODE`。
  - `mvn -B -o clean verify`：**SUCCESS**，155 個測試（Resource Server 47、Authorization Server 99、範例 9）。
- **Decision Log**:
  - **DEC-080**: 第 1 階段第三方登入的 Email 屬於既有帳號時直接拒絕，帳號連結確認於工作 14 加入。
  - **DEC-081**: 第三方登入使用 Spring Boot 標準的 OAuth2 Client 設定。
  - **DEC-082**: `PrincipalNormalizer` 在沒有 factor authority 時加入 `FACTOR_AUTHORIZATION_CODE`。
- **Next TODO**:
  - 工作 10：`example-authorization-server` 改用 AS starter、`example-bff`、E2E 測試。

---
## Step 28: Authorization Server 第 1 階段——工作 10（範例與 E2E），第 1 階段完成
- **Status**: 🟢 Completed（M4 已實作，尚未發佈）
- **Acceptance Criteria**:
  - [x] `example-authorization-server` 改用 AS starter（port 9000、預設 SQLite、示範使用者 alice／bob、角色 A），移除舊的 HS256 示範簽發端點。
  - [x] `example-resource-server` 改以登入服務的 JWKS 驗證 RS256 Token，檢查 `iss` 與 `aud`；移除 HS256 金鑰與測試 JWT CLI。
  - [x] 新增 `example-bff`：oauth2Login、`/me`、`/api/**` 代理（自動附帶並刷新 Access Token，同一位使用者的刷新依序執行）、RP-Initiated Logout、示範頁面。
  - [x] 新增 `e2e-tests`：同一個 JVM 啟動四個應用程式，模擬瀏覽器（T-E2E-01、T-E2E-03、登出）。
  - [x] 新增 [Authorization Server 使用指南](authorization-server/getting-started.md)；改寫 E2E 測試指南與 README 的範例說明。
- **Commands Run & Results**:
  - E2E 4 個測試第一次執行即全數通過：alice 登入後呼叫 API 200、bob 403、audience 不同的服務拒絕同一個 Token、登出後兩邊都需要重新登入。
  - `mvn -B -o clean verify`：**SUCCESS**，161 個測試（Resource Server 47、Authorization Server 99、範例 11、E2E 4）。
  - 文件連結檢查發現 Resource Server 使用指南仍連到已刪除的 `DemoJwtDecoderConfiguration`，已修正。
- **Decision Log**:
  - **DEC-083**: 範例 jar 以 `exec` classifier 產生可執行檔，主要 artifact 維持一般 jar，供 `e2e-tests` 引用。
  - **DEC-084**: E2E 在同一個 JVM 執行，以 `spring.config.name` 避免載入同名的 `application.yml`；不需要 Docker。
  - **DEC-085**: 範例登入服務使用自己的 Session Cookie 名稱，避免與同主機的 BFF 互相覆蓋。
- **Next TODO**:
  - 待使用者決定：授權條款（發佈 2.0.0 的前提）、合併 PR #3 與本分支的 PR、1.1.0 發佈時間。
  - 第 2 階段（工作 11～17）：重用偵測、登出撤銷 Session、登入保護與稽核、帳號連結、排程（金鑰輪換、清理）、Spring Session JDBC、metrics。

---
## Step 29: PR #4 review 修正（10 項全部修正）
- **Status**: 🟢 Completed
- **修正內容**:
  1. 登入 Session 已撤銷或過期、但瀏覽器仍登入時，授權請求原本以 HTTP 500 結束：新增 `LoginSessionValidationFilter`，結束瀏覽器登入並回到登入頁；建立連結時也檢查到期時間。
  2. Starter 對應 `GET /` 會與應用程式的首頁衝突：改為 `/jacky917/signed-in`（需要登入）。
  3. 設定 `spring.flyway.locations` 會讓應用程式在 `db/migration` 的 migration 靜默不執行：改為 Starter 自己的 Flyway 與歷史表（`jacky917_as_schema_history`），migration 移到 `db/jacky917-as/{vendor}`；應用程式的 Flyway 遇到 Starter 的表時以版本 0 建立 baseline。資料庫檔案改為在寫入機密前才設為 600。
  4. BFF 代理：原樣轉送 query、不當成 URI 樣板、自行拒絕 `//` 開頭的路徑。
  5. BFF 的鎖改為固定 64 個。
  6. 新增 9 個單元測試類別（Mockito、固定時鐘、每個分支一個案例），涵蓋原本未測的錯誤路徑；第三方登入無法處理時改為回到登入頁（原本 500）。
  7. 新增可推移的 `Clock` Bean：T-REFRESH-06（Session 超過 90 天）、登入 Session 過期時回到登入頁。
  8. 新增 `/userinfo` 測試。
  9. E2E 只有登入服務事先決定埠號，其餘以 `server.port=0` 啟動；埠號衝突時重試。
  10. 假的 OIDC 提供者每個測試類別各自啟動與關閉，每次登入以授權碼區分。
- **Commands Run & Results**:
  - 破壞實驗：移除 `LoginSessionValidationFilter` → 重現原本的 `IllegalStateException`（500）、過期案例發出授權碼；移除代理的 `//` 檢查 → 代理測試失敗；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，215 個測試（Resource Server 47、Authorization Server 150、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-086**: Starter 的 migration 使用自己的 Flyway 與歷史表，不改變應用程式的 Flyway。
  - **DEC-087**: 登入 Session 失效時結束瀏覽器登入（重新登入），而不是拒絕授權。
  - **DEC-088**: Starter 的頁面一律放在 `/jacky917/` 之下。

---
## Step 30: 第二次 review 修正（使用者的 8 項審查）
- **Status**: 🟢 Completed
- **確認結果**：8 項中 7 項正確；第 3 項（側檔權限）方向正確但嚴重度較低：實測在目前的啟動順序下側檔已是 600，只是順序沒有保證。
- **修正內容**:
  1. ES256 時每次簽發都失敗：新增 `ActiveKeyJwtEncoder`，一律以目前金鑰的演算法簽章；授權流程測試另以 ES256 完整執行。
  2. 發佈流程的授權條款檢查被註解中的字樣騙過：改以 XML 解析（`scripts/has-declared-license.py`），並改寫 TODO 註解。
  3. 調整權限時一併處理 `-wal`、`-shm`；Starter 建立的資料夾為 `700`。
  4. Authorization Server 模組 2.1.0 起才發佈（使用者決定）：設 `maven.deploy.skip`，並從 BOM 移除。
  5. 移除誤提交的空資料庫檔案。
  6. 新增 `login.providers`；未設定時依名稱排序（測試發現 Spring Boot 預設 repository 的順序不固定）；無法列出時於啟動時警告。
  7. `Columns`：共用的截斷與欄位長度常數（不切斷 emoji）。
  8. 同一次 token 請求內重複使用使用者與登入 Session 的查詢（約 8 次降為 5 次）。
- **Commands Run & Results**:
  - 以 ES256 執行授權流程：修正前 12／18 失敗（`Failed to select a JWK signing key`），修正後 18／18 通過。
  - 授權條款檢查：目前的 `pom.xml` 回傳 1（拒絕發佈）；加入 `<licenses>` 後回傳 0。
  - `mvn help:evaluate -Dexpression=maven.deploy.skip`：AS 兩個模組為 `true`，Resource Server 未設定。
  - `mvn -B -o clean verify`：**SUCCESS**，242 個測試（Resource Server 47、Authorization Server 177、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-089**: Authorization Server 於 2.1.0 起發佈並加入 BOM（使用者決定）。
  - **DEC-090**: Token 一律以目前金鑰的演算法簽章（在 encoder 處理，而不是 customizer）。

---
## Step 31: 授權條款（MIT）
- **Status**: 🟢 Completed
- **使用者決定**：使用最寬鬆、主流的授權條款 → **MIT License**。
- **變更**：新增根目錄 `LICENSE`；根 POM 宣告 `<licenses>`（MIT），移除 TODO；README 新增「授權條款」；設計文件更新。
- **Commands Run & Results**:
  - `scripts/has-declared-license.py pom.xml`：`declared licenses: MIT License`（發佈流程的檢查通過）。
  - flatten 後發佈的 POM（resource server starter、BOM、relocation）只帶 `MIT License`，不再有繼承的 Apache License 2.0。
- **Decision Log**:
  - **DEC-091**: 授權條款為 MIT（解決 DEC-058 的待決事項）。
- **Next TODO**:
  - 發佈 2.0.0：修改 `<revision>` 為 `2.0.0`，建立 `v2.0.0` tag 與 Release。
  - `1.x` 分支是否也加入 MIT（目前只有 `main` 有 `LICENSE`）。

---
## Step 32: 準備發佈 2.0.0（M3）
- **Status**: 🟢 發佈 commit 已準備（等待合併後建立 `v2.0.0` Release）
- **變更**：`<revision>` 改為 `2.0.0`；README、使用指南、GitHub Packages 指南移除「尚未發佈」的說明並改用 `2.0.0`；新增 `CHANGELOG.md`；`1.x` 分支另開 PR 加入 MIT（PR #6）。
- **發佈前演練（與 publish.yml 相同的檢查）**:
  - tag 檢查：`revision=2.0.0`，與 `v2.0.0` 一致。
  - 授權條款檢查：`declared licenses: MIT License`。
  - `mvn -B -o clean verify`：**SUCCESS**，242 個測試。
  - 會發佈的模組（版本 2.0.0）：`jacky917-security-core`、`-annotations`、`-resource-server-autoconfigure`、`-resource-server-starter`、`-bom`、舊座標 relocation `com.github.jacky917:jacky917-security-starter`，以及根 parent POM；Authorization Server、範例、E2E 皆為 `maven.deploy.skip=true`。
- **發佈步驟**：合併本 PR → 在 GitHub 建立 tag `v2.0.0` 與 Release（內容可使用 `CHANGELOG.md` 的 2.0.0 一節）→ 發佈流程自動檢查、測試並部署。
- **Next TODO**:
  - 發佈後把 `main` 的 `<revision>` 改為 `2.1.0-SNAPSHOT`。
  - 以外部專案從 GitHub Packages 實際下載 2.0.0 驗證（含舊座標的 relocation）。

---
## Step 33: 開始 2.1.0 的開發版本
- **Status**: 🟢 Completed（`v2.0.0` Release 建立後合併）
- **變更**：根 POM 的 `<revision>` 改為 `2.1.0-SNAPSHOT`。
- **注意**：`v2.0.0` 的 tag 必須建在版本為 `2.0.0` 的 commit（`303f62f`）上；若誤建在之後的 commit，發佈流程的 tag 檢查會中止發佈（`2.1.0-SNAPSHOT` ≠ `2.0.0`）。

---
## Step 34: Authorization Server 第 2 階段——工作 11（Refresh Token 重用偵測）
- **Status**: 🟢 Completed
- **變更**:
  - `RefreshTokenReuseDetector`：在 token 端點取代 Spring 的刷新 provider。每次刷新在同一個交易中：鎖定授權列（PostgreSQL `FOR UPDATE`、SQLite `IMMEDIATE`）、檢查登入 Session 與使用者、交給 Spring 簽發、把舊 token 的 SHA-256 記錄到 `refresh_token_history`、更新 `last_seen_at`。
  - 已輪換的 token 再次出現：寬限期（`refresh.reuse-grace-period`，30 秒）內只拒絕；超過則撤銷登入 Session（`REUSE_DETECTED`，最新的 Refresh Token 一併失效）並寫入 `login_audit`。
  - 使用者停用（含管理員鎖定、已刪除）或登入後變更密碼：拒絕並撤銷（`USER_DISABLED`、`PASSWORD_CHANGED`）。
  - `AuthSessionService`：`revoke`、`revokeAll`（同一個交易中刪除授權）、`touch`、`findActive`。
  - 稽核基礎：`LoginAuditEvent`、`JdbcLoginAuditListener`（交易結束後發布，寫入失敗只記錄日誌）。
  - 新設定：`refresh.reuse-grace-period`（0～2 分鐘）、`refresh.history-retention`（24 小時，1 小時～Refresh Token 有效期）。
  - Dialect：`lockAuthorizationByRefreshTokenSql` 改為以授權 ID 鎖定的 `lockAuthorizationSql`。
- **行為調整**：暫時鎖定（`locked_until`）不再阻擋刷新，只阻擋密碼登入；否則任何人故意輸錯密碼就能讓帳號持有人所有裝置被登出。
- **Commands Run & Results**:
  - 新增整合測試（SQLite、PostgreSQL 各一次）：T-REFRESH-01～05、寬限期內不撤銷、暫時鎖定仍可刷新；`RefreshTokenReuseDetectorTest` 13 個分支。
  - 破壞實驗：移除列鎖後，PostgreSQL 的併發刷新測試 3 次全部失敗（兩個請求都成功）；還原後通過。
  - 第一次執行時寬限期測試失敗：測試推移剛好 30 秒，加上測試本身的時間就超過寬限期，改為 29 秒。
  - `mvn -B -o clean verify`：**SUCCESS**，278 個測試（Resource Server 47、Authorization Server 213、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-092**: 暫時鎖定只阻擋密碼登入，不阻擋已登入 Session 的刷新。
  - **DEC-093**: 稽核事件由元件在交易結束後發布，不使用 `@TransactionalEventListener`。
  - **DEC-094**: 列鎖以授權 ID 進行，鎖定後重新讀取授權。

---
## Step 35: Authorization Server 第 2 階段——工作 12（登出、帳號頁）
- **Status**: 🟢 Completed
- **變更**:
  - `Jacky917LogoutHandler`：RP-Initiated Logout（`/connect/logout`）與登入服務的 `POST /logout` 撤銷整個登入 Session（`LOGOUT`，授權一併刪除），並寫入 `login_audit`。登入 Session 從瀏覽器 Session 與 `id_token_hint` 兩處尋找，瀏覽器 Session 過期、ID Token 過期時仍可登出。
  - 帳號頁 `/jacky917/account`：登入中的裝置（登入方式、時間、IP、瀏覽器、目前的裝置），登出單一裝置或所有裝置（`LOGOUT_ALL`）；不能登出他人的 Session（404）。
  - `LoginSessionValidationFilter` 也套用到登入頁的 filter chain：在其他裝置被登出的瀏覽器回到登入頁。
  - `AuthSession` 加入 `ipAddress`、`userAgent`；登入頁新增「已登出」訊息；已登入頁連到帳號頁；`PageSupport` 抽出頁面共用的文字與品牌設定。
  - 測試重構：`AbstractFlowIntegrationTest` 抽出共用的 `@SpringBootTest` 設定與模擬瀏覽器、BFF 的工具。
- **Commands Run & Results**:
  - 新增 `*LogoutIntegrationTest`（SQLite、PostgreSQL 各 11 個）、`Jacky917LogoutHandlerTest`（5 個）。
  - 第一次執行時 RP-Initiated Logout 測試都回 400：登出端點的 GET 只讀 query string，而 MockMvc 的 `param()` 不會放進 query string；「未註冊的 redirect URI」測試因此是以錯誤的原因通過。改以 query string 傳送，並在該測試中確認拒絕的原因是 `post_logout_redirect_uri`。
  - 破壞實驗：不設定登出處理器時，3 個 RP-Initiated Logout 測試失敗；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，305 個測試（Resource Server 47、Authorization Server 240、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-095**: 登出時，瀏覽器 Session 與 `id_token_hint` 所屬的登入 Session 都撤銷。
  - **DEC-096**: 帳號頁放在 `/jacky917/account`，時間以伺服器的預設時區顯示。

---
## Step 36: Authorization Server 第 2 階段——工作 13（登入保護與稽核）
- **Status**: 🟢 Completed
- **變更**:
  - `LoginFailureHandler`：既有帳號的密碼錯誤才計數；連續 `login-protection.max-failures`（5）次時鎖定 `lock-duration`（15 分鐘）並發布 `ACCOUNT_LOCKED`；鎖定期間的嘗試不延長鎖定；所有失敗都寫入 `LOGIN` 稽核（`LoginFailureReason`），頁面訊息相同。
  - `LoginAttemptGuard`：同一個 IP 最近一分鐘失敗 `max-failures-per-ip-per-minute`（20）次後，在檢查密碼之前就拒絕（`/login?error=rate_limited`）。
  - 密碼登入與第三方登入的成功、失敗都寫入 `login_audit`。
  - `UserAccountService#recordLoginFailure`：單一 `UPDATE` 完成計數與鎖定。
  - 新設定：`login-protection.*`。
- **Commands Run & Results**:
  - 新增 `*LoginProtectionIntegrationTest`（SQLite、PostgreSQL 各 5 個）、`LoginAttemptGuardTest`、`LoginFailureHandlerTest`；Google 登入整合測試加上稽核的檢查。
  - 第一次執行時 IP 限流沒有生效：filter 以 servlet path 判斷 `/login`，而 servlet path 依部署方式可能為空（MockMvc 即是如此）；改以 request URI 判斷。
  - 鎖定時間在 SQLite 只保存到毫秒：寫入前先截斷，讀回後才能正確判斷「此次失敗造成鎖定」。
  - `mvn -B -o clean verify`：**SUCCESS**，324 個測試（Resource Server 47、Authorization Server 259、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-097**: 鎖定時失敗次數歸零；對已鎖定帳號的嘗試不延長鎖定。
  - **DEC-098**: 被限流拒絕的嘗試也計入該 IP 的失敗。

---
## Step 37: Authorization Server 第 2 階段——工作 14 之一（帳號連結）
- **Status**: 🟢 Completed（GitHub、LINE 為工作 14 之二）
- **變更**:
  - 第三方登入的已驗證 Email 屬於既有帳號時，不再直接拒絕：保存待確認的連結（`user_action_token`，10 分鐘、只用一次），導向 `/jacky917/link-account`。使用者以原帳號的密碼，或以原帳號已連結的提供者登入確認後才連結並登入；取消則什麼都不建立。`account-linking.mode: manual-only` 時維持直接拒絕。
  - 連結頁的密碼錯誤計入帳號鎖定與 IP 限流。
  - 帳號頁：已連結的帳號、「連結」（以該提供者登入後連結到目前的使用者並還原原本的登入）、「解除連結」（不能解除唯一的登入方式）；寫入 `ACCOUNT_LINKED`、`ACCOUNT_UNLINKED`。
  - 已連結帳號的第三方登入不再受暫時鎖定影響（與 DEC-092 一致）。
  - 重構：`IdentityProviders`（登入頁與帳號頁共用）、`LoginCompletion`（完成登入）、`Hashes`（SHA-256）；第三方登入測試抽出 `AbstractGoogleIntegrationTest`。
- **Commands Run & Results**:
  - 新增 `*AccountLinkingIntegrationTest`（SQLite、PostgreSQL 各 6 個）、`ManualOnlyAccountLinkingIntegrationTest`；`FederatedLoginSuccessHandlerTest` 新增 `LINK_REQUIRED`。
  - 破壞實驗：略過連結頁的密碼檢查、不完成待確認連結 → 對應的 2 個測試失敗；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，338 個測試（Resource Server 47、Authorization Server 273、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-099**: 連結確認的 token 只放在瀏覽器 Session，不放在網址中。
  - **DEC-100**: 帳號頁發起的連結完成後還原原本的登入，不建立新的登入 Session。
  - **DEC-101**: 不能解除唯一的登入方式。

---
## Step 38: Authorization Server 第 2 階段——工作 14 之二（GitHub、LINE）
- **Status**: 🟢 Completed（工作 14 完成）
- **變更**:
  - `GitHubFederatedUserInfoMapper`：數字 `id` 為 subject；Email 取自 `/user/emails` 中主要且已驗證的地址（需要 `user:email`），失敗時沒有 Email 但仍可登入；公開 Email 不採信。
  - `LineIdTokens`：`JwtDecoderFactory<ClientRegistration>` Bean，LINE 的 ID Token 以 channel secret 驗證 HS256，其他提供者維持 RS256。
  - 使用指南：Google、GitHub、LINE 的設定範例與差異。
- **查證**：LINE Developers 文件——網頁登入的 ID Token 以 HS256、channel secret 簽署；沒有 `email_verified` claim。
- **Commands Run & Results**:
  - 新增 `ExternalProvidersIntegrationTest`（假的 GitHub 與 LINE，5 個）與 `GitHubFederatedUserInfoMapperTest`（3 個）。
  - 破壞實驗：LINE 改回 RS256 → LINE 登入失敗（`Signed JWT rejected`）；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，346 個測試（Resource Server 47、Authorization Server 281、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-102**: LINE 的 Email 一律視為未驗證，不用於比對既有帳號。
  - **DEC-103**: GitHub 的 Email 端點由使用者資訊端點推得，以支援 GitHub Enterprise Server。

---
## Step 39: Authorization Server 第 2 階段——工作 15（排程：金鑰輪換、清理）
- **Status**: 🟢 Completed
- **變更**:
  - `SigningKeyRotation`：使用滿 `rotation-period − announce-period`（89 天）時建立並公開 `NEXT`；公開滿 `announce-period`（1 天）後啟用，舊金鑰改為 `RETIRING`；`max(Access Token, 30 分鐘) + 5 分鐘` 後退役。
  - `DataCleanup`：資料模型 §14.1 的清理規則，分批刪除（`cleanup.batch-size`）；過期的登入 Session 改為 `EXPIRED` 並刪除其授權。
  - `ScheduledJobLock`：以 `shedlock` 表讓每個週期只有一個實例執行（不引入 ShedLock）。
  - `MaintenanceScheduler`：自己的執行緒排程，不啟用應用程式的 `@Scheduled`；啟動後經過一個週期才第一次執行。
  - 新設定：`keys.rotation-enabled`、`keys.rotation-period`、`keys.announce-period`、`cleanup.*`；`SigningKeyStore` 新增 `findByStatus`、`deleteRetiredBefore`。
- **查證**：Spring Authorization Server 7.1.1 的 `JwtGenerator` 以固定 30 分鐘簽發 ID Token。
- **Commands Run & Results**:
  - 新增 `*MaintenanceIntegrationTest`（SQLite、PostgreSQL 各 5 個）、`MaintenanceSchedulerTest`（3 個）。
  - 破壞實驗：清理授權時拿掉「至少有一個 token」的條件 → 等待同意中的授權被刪除，測試失敗；還原後通過。
  - `mvn -B -o clean verify`：**SUCCESS**，360 個測試（Resource Server 47、Authorization Server 295、範例 14、E2E 4）。
- **Decision Log**:
  - **DEC-104**: 排程鎖自行實作（使用既有的 `shedlock` 表），持有到週期的 9 成、不提早釋放。
  - **DEC-105**: 排程使用 starter 自己的執行緒，不使用 `@EnableScheduling`、不註冊 `TaskScheduler` Bean。

---
## Step 40: Authorization Server 第 2 階段——工作 16（多實例：Spring Session JDBC）
- **Status**: 🟢 Completed
- **變更**:
  - 多實例的瀏覽器 Session：應用程式加入 `spring-boot-starter-session-jdbc` 即由 Spring Boot 啟用（`SPRING_SESSION` 表已在 V1 migration 中）。Starter 對 `spring-session-core` 為選用依賴。
  - `AuthorizationServerSessionRegistryAutoConfiguration`：有 Spring Session 時，OIDC 的 Session registry 改為 `SpringSessionBackedSessionRegistry`。
  - E2E：`MultiInstanceEndToEndTest`（兩個登入服務 + embedded PostgreSQL + Spring Session JDBC，前面是輪流轉送的 `RoundRobinProxy`）；原本的 E2E 也改以 Spring Session JDBC 執行（SQLite）；啟動工具抽出為 `E2eApplications`。
- **查證**：Spring Authorization Server 7.1.1 預設的 Session registry 在記憶體中，token 端點以它產生 ID Token 的 `sid`；Spring Session 的 `SpringSessionBackedSessionRegistry` 的 `registerNewSession` 為空操作。Spring Boot 4.1.1 的 Session 自動配置類別名稱已對照 jar 確認（Redis 為 `SessionDataRedisAutoConfiguration`，原本猜錯，已修正）。
- **Commands Run & Results**:
  - 多實例 E2E 2 個測試通過；破壞實驗：登入服務改用記憶體 Session → 2 個測試都失敗（登入頁的 CSRF 在另一個實例無效）；還原後通過。
  - 新增 `SessionRegistryAutoConfigurationTest`（2 個）。
  - `mvn -B -o clean verify`：**SUCCESS**，371 個測試（Resource Server 47、Authorization Server 297、範例 14、E2E 6）。
- **Decision Log**:
  - **DEC-106**: Spring Session JDBC 為選用：多實例時由應用程式加入依賴。

---
## Step 41: Authorization Server 第 2 階段——工作 17（Metrics、健康檢查），第 2 階段完成
- **Status**: 🟢 Completed（第 2 階段：工作 11～17 全部完成，尚未發佈）
- **變更**:
  - `AuthorizationServerMetrics`（應用程式有 Micrometer 時）：`jacky917.as.login`、`token.issued`、`refresh.reuse_detected`、`refresh.grace_rejected`、`refresh.rejected`、`session.active`、`signing_key.age`、`cleanup.deleted`。
  - `SigningKeyHealthIndicator`（應用程式有 Spring Boot 健康檢查時）：沒有 `ACTIVE` 金鑰時 `DOWN`；`rotationOverdue`。
  - 新事件：`AccessTokenIssuedEvent`、`RefreshTokenRejectedEvent`、`DataCleanupEvent`；Micrometer 與 `spring-boot-health` 為選用依賴。
  - 使用指南：§4.5 監控；「目前的限制」只剩第 3 階段以後的項目。
- **查證**：Spring Boot 4.1.1 的 `HealthIndicator` 位於 `org.springframework.boot.health.contributor`（`spring-boot-health`）；metrics 自動配置類別名稱已對照 jar。
- **Commands Run & Results**:
  - 新增 `ObservabilityIntegrationTest`（3 個）、`SigningKeyHealthIndicatorTest`（2 個）；`Jacky917TokenCustomizerTest`、`RefreshTokenReuseDetectorTest` 加上事件的檢查。
  - 第一次執行時 `session.active` 為 0：測試在重用偵測撤銷 Session 之後才讀 gauge，改為登入後立即讀取。
  - `mvn -B -o clean verify`：**SUCCESS**，377 個測試（Resource Server 47、Authorization Server 303、範例 14、E2E 6）。
  - `CHANGELOG.md` 新增 `[Unreleased]`：Authorization Server starter（第 1、2 階段）。
- **待使用者決定**：第 2 階段在分支 `claude/as-phase-2`，合併到 `main`（`2.1.0-SNAPSHOT`）之後，原規劃的 2.2.0 是否改為隨 2.1.0 發佈、AS 是否在 2.1.0 即轉為正式版。

---
## Step 42: Authorization Server 第 2 階段——多面向審查的修正
- **Status**: 🟢 Completed（尚未發佈）
- **背景**：對 `claude/as-phase-2`（工作 11～17）做多面向審查（一般品質、測試覆蓋、錯誤處理、註解、型別設計），依審查結果修正全部 Critical、Important 與建議事項。
- **變更**:
  - 登入保護：只有 `BadCredentialsException` 計入帳號鎖定，非預期錯誤記為 `ERROR` 不計數；`LoginAttemptGuard` 以解碼後的路徑比對（`/%6Cogin` 不再繞過限流）；鎖定改為兩個條件互斥的 `UPDATE`，只有實際鎖定的那一次回傳 `true`；新增 `LockoutPolicy`、`AccountLockout`（登入頁與連結確認頁共用）。
  - GitHub：只有 403／404 視為沒有 Email，其他錯誤讓登入失敗（避免建立重複帳號）；支援 GitHub Enterprise Server 的 `/api/v3/user`。
  - 帳號連結：用掉待確認連結與建立連結在同一個交易（`PendingLinkService#confirm`，連結以 savepoint 加入）；所有失敗都有日誌、`ACCOUNT_LINKED` 失敗稽核與具體訊息；連結確認頁的重導加上 context path；新增 `FederatedLoginFailureHandler`；`unlink` 回傳 `UnlinkResult`。
  - 登出：撤銷失敗時仍清除瀏覽器登入；「登出所有裝置」在一個交易中完成。
  - 稽核與 metrics：稽核寫入失敗記錄完整事件並發布 `LoginAuditWriteFailedEvent`；排程每一步各自執行、失敗時釋放鎖並發布 `MaintenanceFailedEvent`；新增 `audit.write_failures`、`maintenance.failures`；`cleanup.deleted` 的標籤改為 `target`；metrics listener 的失敗不影響請求；健康檢查在停用輪換時不回報逾期。
  - 型別：`LoginAuditEvent` 的失敗原因與登入方式改為 enum；`CleanupTarget`；`FederatedLoginRejectedException` 改用 factory；`AuthSession`、`LinkIntent`、`RotatedRefreshToken`、各事件在建構時檢查。
  - 註解與文件：修正事實錯誤的 Javadoc，更新使用指南與詳細設計 §7.2、§8.2、§13.2。
  - 本文件 Step 41 原本寫「第 2 階段已合併到 `main`」，實際尚未合併，已更正。
- **Commands Run & Results**:
  - 新增測試：帳號接管情境、連結確認頁的鎖定／停用／連續失敗、Refresh Token 仍有效的授權不被清除、偽造的 LINE ID Token、GitHub 故障、併發的登入失敗、`SigningKeyRotation`、`LinkIntent` 序列化等；併發刷新測試改為必定重疊。
  - `mvn -B -o verify`：**SUCCESS**（Authorization Server 345 個測試，原本 303 個）；`scripts/check-doc-links.py`：0 個問題。
- **Decision Log**:
  - **DEC-107**: 排程工作成功時不提早釋放鎖，失敗時釋放，讓任何實例的下一次排程即可重試。
  - **DEC-108**: 排程的首次執行維持「啟動後一個週期」；每天部署的應用程式改由管理工作呼叫 `DataCleanup#runAll()`（文件說明），避免重啟時所有工作一起執行。
  - **DEC-109**: 重用以外的刷新拒絕不寫入稽核（資料庫的事件類型 CHECK 約束不允許新類型），以 metric 與 `auth_session.revoke_reason` 記錄。
- **Next TODO**:
  - 合併 PR 後，決定第 2 階段的發佈版本，以及 AS 是否轉為正式版。

---
## Step 43: Authorization Server 第 3、4 階段詳細設計
- **Status**: 🟢 設計完成（分支 `claude/as-phase-3`）
- **範圍**（使用者確認的目標）：A 使用者與權限管理（Admin API）、B 帳號自助功能（註冊、Email 驗證、忘記／變更密碼）、C 第三方應用（同意畫面、client 與 scope 管理、`aud` 依 scope 決定）、D 兩步驟驗證（TOTP）、E 發佈準備（不發佈）。Apple 登入、即時撤銷、Redis、KMS、MySQL 不列入。
- **變更**：新增 `docs/design/auth-server-phase3-4-design.md`（決策 D23～D31、資料表變更、Admin API、帳號頁面、同意畫面、TOTP、設定屬性、工作 18～29、測試案例）。
- **Decision Log**:
  - **DEC-110**: Admin API 以本 AS 簽發的 Bearer token 驗證，依 `as:*` 權限在 request 層級授權；不提供管理畫面（D23、D24）。
  - **DEC-111**: 寄信以 `AccountMailer` SPI 抽象；沒有寄信方式時不提供需要寄信的功能，啟用註冊則啟動失敗（D26）。
  - **DEC-112**: TOTP 自行實作（RFC 6238），密鑰以既有的主金鑰加密；QR code 使用 ZXing（D31）。
- **Next TODO**:
  - 工作 18：Admin API 基礎與 migration V1_1_0。

---
## Step 44: Authorization Server——工作 18（Admin API 基礎）
- **Status**: 🟢 Completed
- **變更**:
  - Migration V1_1_0（兩種資料庫）：`app_user.password_change_required`；`login_audit` 新增 7 種事件（註冊、Email 驗證、重設密碼、兩步驟驗證的啟用與停用、同意與撤回）；`admin_audit_log` 新增對象種類 `API_RESOURCE`。SQLite 無法修改約束，以重建資料表的方式完成。
  - `/admin/api/**` 的 Order 2 filter chain：只接受本 AS 簽發、`aud` 包含 `admin-api.audience` 的 Bearer token；使用者 token 以 `permissions` 中的 `as:*`、`client_credentials` token 以 `as:*` scope 授權；無狀態、無 CSRF。
  - `AdminApiExceptionHandler`（RFC 9457 Problem Details，只處理管理 API 的 controller）、`PageResult`、`AdminAuditService`（`admin_audit_log`，在呼叫端的交易中寫入）、`AdminOperator`。
  - 稽核查詢：`GET /admin/api/audit/logins`、`GET /admin/api/audit/admin`（篩選、分頁、新的在前）。
  - 屬性：`admin-api.enabled`、`admin-api.audience`。
- **Commands Run & Results**:
  - 新增 `AdminApiIntegrationTest`（SQLite、PostgreSQL 各 6 個）：401／403、`client_credentials` 的 scope、稽核查詢與篩選、Problem Details、新的稽核值可以寫入。
  - `mvn -B -o test`（AS 模組）：**SUCCESS**，357 個測試。

---
## Step 45: Authorization Server——工作 19（管理 API：使用者）
- **Status**: 🟢 Completed
- **變更**:
  - `UserAdminService`、`UserAdminController`：`GET/POST /admin/api/users`（搜尋帳號、Email、顯示名稱，`%`、`_` 視為一般字元）、`GET/PATCH/DELETE /admin/api/users/{id}`、`POST …/unlock`、`PUT …/password`、`PUT/DELETE …/roles/{role}`（可設定到期時間）、`GET/DELETE …/sessions`、`DELETE /admin/api/sessions/{asid}`。
  - 讓使用者無法登入（`LOCKED`、`DISABLED`、刪除）時撤銷所有登入 Session（`USER_DISABLED`）；管理員設定密碼時撤銷所有登入 Session（`PASSWORD_CHANGED`），預設下次登入必須變更。
  - 管理員不能停用或刪除自己，也不能移除自己最後一個擁有 `as:user:write` 的角色。
  - 每個寫入操作與 `admin_audit_log` 在同一個交易中；快照不含密碼雜湊。
  - `UserAccount` 新增 `passwordChangeRequired`。
- **Commands Run & Results**:
  - `AdminApiIntegrationTest` 新增 9 個（兩種資料庫）：建立使用者後登入的 token 帶有角色與權限、`AS_SUPPORT` 不能寫入、搜尋、停用撤銷 Session、部分更新與 409、設定密碼與解鎖、角色指派與到期、保護操作者自己、登入 Session 管理。
  - `mvn -B -o test`（AS 模組）：**SUCCESS**，375 個測試。
- **Decision Log**:
  - **DEC-113**: 管理 API 直接操作預設的使用者資料表；以其他使用者來源取代 `UserAccountService` 的應用程式應關閉管理 API 或自行提供。

---
## Step 46: Authorization Server——工作 20（管理 API：角色與權限），群組 A 完成
- **Status**: 🟢 Completed
- **變更**:
  - `RoleAdminService`、`RoleAdminController`：`GET/POST /admin/api/roles`、`GET/PUT/DELETE /admin/api/roles/{code}`、`GET/POST /admin/api/permissions`、`GET/PUT/DELETE /admin/api/permissions/{code}`。
  - 代碼格式依資料模型 §5.1；`as:` 開頭的權限保留給登入服務。內建角色與權限不能刪除、不能改代碼；`AS_ADMIN` 的權限不能變更；仍有使用者的角色、仍被角色或 scope 使用的權限不能刪除。
  - 使用指南新增 §9 管理 API（驗證、權限、端點、規則）；「目前的限制」與「上線檢查清單」改為 §10、§11。
- **Commands Run & Results**:
  - `AdminApiIntegrationTest` 新增 5 個（兩種資料庫）：業務角色與權限出現在使用者的 token 中、代碼驗證、內建保護、刪除規則、更新權限清單與 403。

---
## Step 47: Authorization Server——工作 21（寄信 SPI）
- **Status**: 🟢 Completed
- **變更**:
  - `AccountMailer` SPI 與三種實作：`SpringAccountMailer`（應用程式有 `JavaMailSender` 時，必須設定 `account.mail.from`）、`LoggingAccountMailer`（`account.mail.log-links=true`，僅限開發，建立時警告）、`UnavailableAccountMailer`（沒有寄信方式）。應用程式自己的 Bean 優先。
  - `AccountMailContent`：信件主旨與內文取自 starter 的訊息檔（`mail.*`，英文與繁中），可覆寫。
  - `ActionTokenService`：`EMAIL_VERIFY`、`PASSWORD_RESET` 的一次性 token（只存 SHA-256、新的取代舊的、60 秒內不重複發出、只能使用一次）。
  - `AccountLinks`：以 `issuer` 產生信件中的連結（不依賴請求的 Host 標頭）。
  - 屬性 `account.registration.enabled`、`account.email-verification-ttl`、`account.password-reset-ttl`、`account.mail.from`、`account.mail.log-links`；`spring-boot-starter-mail` 為選用依賴。
- **Commands Run & Results**:
  - 新增 `AccountMailTest`（5 個）、`AccountConfigurationIntegrationTest`（5 個，token 的部分在 SQLite 與 PostgreSQL 各執行一次）。

