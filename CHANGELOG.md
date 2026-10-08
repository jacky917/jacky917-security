# 變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本號遵循 [語意化版本](https://semver.org/lang/zh-TW/)。

## [2.0.0] - 2026-10-08

**破壞性更新**：升級到 Spring Boot 4.1，Maven 座標改名。從 1.x 升級請先讀 [升級到 2.0](docs/guides/upgrade-to-2.0.md)。

### 平台

- Spring Boot **4.1.1**、Spring Security 7.1.1、Jackson 3。需要 Java 21 以上。
- Spring Boot 3.5 的專案請繼續使用 `1.x`（只提供安全修補）。

### 座標與模組（破壞性）

- groupId 改為 `io.github.jacky917`；starter 改名為 `jacky917-security-resource-server-starter`。
- 新增 `jacky917-security-bom`（統一管理版本）與 `jacky917-security-core`（claim 名稱與權限前綴，無任何依賴）。
- 自動配置的套件改為 `jacky917.security.resourceserver.autoconfigure`。
- 舊座標 `com.github.jacky917:jacky917-security-starter` 在 2.0.x 以 relocation 導向新座標，3.0 移除。
- 發佈的 POM 不再需要 parent（flatten），也不再繼承 Spring 專案的授權條款與開發者資訊。

### 行為變更（破壞性）

- `@RequireRole`／`@RequirePerm`／`@RequireScope` 跟隨 `jacky917.security.jwt.prefix.*` 設定的前綴。
- `permit-all-patterns` 預設只放行 `/actuator/health`；Swagger／OpenAPI 需要自行加入。
- 移除 `jacky917.security.debug-log`（改用 `logging.level`）與 `jacky917.security.method-security.enabled`（方法級授權一律啟用）。
- 401／403 的日誌改為 DEBUG；錯誤回應改用應用程式的 Jackson 設定。
- 401 的 `WWW-Authenticate` 帶 RFC 9728 的 `resource_metadata`；Spring Security 7 會加入 `FACTOR_BEARER` authority。

### 新增

- `jacky917.security.enabled=false` 或非 Servlet 應用程式中，`@Require*` 註解所需的 Bean 仍會註冊。
- CI：Java 21 與 25 建置測試、文件連結檢查；發佈前檢查 tag 與版本一致、已宣告授權條款，並在全部測試通過後才部署。

### 授權條款

- 以 [MIT License](LICENSE) 授權。

### 預覽（不隨 2.0.0 發佈）

- Authorization Server starter（OAuth 2.0／OIDC 登入服務），2.1.0 起發佈，見 [使用指南](docs/authorization-server/getting-started.md)。

## [1.0.0]

- 第一個發佈版本（Spring Boot 3.5）。GitHub Release 的 tag 是 `v1.0.1`，但發佈的版本為 `1.0.0`（tag 與版本不一致的問題，2.0 的發佈流程已加上檢查）。之後的 1.x 版本見 [`1.x` 分支](https://github.com/jacky917/jacky917-security/tree/1.x)。

[2.0.0]: https://github.com/jacky917/jacky917-security/releases/tag/v2.0.0
[1.0.0]: https://github.com/jacky917/jacky917-security/releases/tag/v1.0.1
