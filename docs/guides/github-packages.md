# GitHub Packages 發佈與引用指南

本文件說明本專案發佈到 GitHub Packages 的標準配置，並對應常見 `422 Unprocessable Entity` 問題。

---

## 1. 發佈座標（已對齊）

| | 2.x（`main`） | 1.x（`1.x` 分支） |
|---|---|---|
| `groupId` | `io.github.jacky917` | `com.github.jacky917` |
| Starter | `jacky917-security-resource-server-starter` | `jacky917-security-starter` |
| 版本 | 開發中 `2.0.0-SNAPSHOT`（尚未發佈） | 已發佈 `1.0.0` |

2.x 發佈的模組：`jacky917-security-core`、`jacky917-security-annotations`、`jacky917-security-resource-server-autoconfigure`、`jacky917-security-resource-server-starter`、`jacky917-security-bom`，以及只在 2.0.x 發佈的舊座標 relocation `com.github.jacky917:jacky917-security-starter`。

版本號只在根 `pom.xml` 的 `<revision>` 定義一次（CI-friendly 版本）。發佈時由 `flatten-maven-plugin` 產生**不含 parent 的獨立 POM**，使用者解析依賴時不需要本專案的 parent，也不需要 Spring Boot 的 parent。

> 重點：子模組不自行定義專案版本，全部繼承父模組版本。

---

## 2. 根 POM 的 distributionManagement

已使用以下設定（`pom.xml`）：

```xml
<distributionManagement>
    <repository>
        <id>github</id>
        <name>GitHub Packages</name>
        <url>https://maven.pkg.github.com/jacky917/jacky917-security</url>
    </repository>
</distributionManagement>
```

---

## 3. 本機 `~/.m2/settings.xml`

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              https://maven.apache.org/xsd/settings-1.0.0.xsd">
    <servers>
        <server>
            <id>github</id>
            <username>jacky917</username>
            <password>YOUR_GITHUB_PAT</password>
        </server>
    </servers>
</settings>
```

PAT 至少需包含：

- 發佈：`write:packages`
- 讀取：`read:packages`

---

## 4. 範例模組不發佈

`examples/example-resource-server` 與 `examples/example-authorization-server` 已設定：

```xml
<properties>
    <maven.deploy.skip>true</maven.deploy.skip>
</properties>
```

確保只發佈函式庫模組，不把範例推上套件倉庫。

---

## 5. GitHub Actions 發佈流程

實際設定見 [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml)。在 GitHub 上**發佈 Release** 時觸發：

流程：

1. **檢查版本**：tag（去掉開頭的 `v`）必須等於根 `pom.xml` 的 `<revision>`，否則中止發佈。
2. **建置、測試並發佈**：`mvn --batch-mode deploy`，部署整個 reactor（含測試）。範例模組以 `maven.deploy.skip` 排除；新增模組時不必修改 workflow。

發佈新版本的步驟：

1. 修改根 `pom.xml` 的 `<revision>`（例如 `2.0.0`）。
2. 在本機執行 `mvn clean verify` 確認通過。
3. Commit 並 push，等 CI 通過。
4. 在 GitHub 建立與版本相同的 tag（例如 `v2.0.0`）與 Release，按下 Publish，等待 workflow 完成。
5. `1.x` 的版本在 `1.x` 分支上建立 tag 與 Release；workflow 使用該分支上的設定。

注意：

- GitHub Packages 的正式版本**不可覆蓋**，同一版本號重複發佈會得到 `409 Conflict` 或 `422`。
- 1.x 曾發生「建立 `v1.0.1` Release，但 `pom.xml` 仍是 `1.0.0`」的情況；2.x 的版本檢查會直接讓這種發佈失敗。

---

## 6. 消費端引用範例

```xml
<dependency>
    <groupId>io.github.jacky917</groupId>
    <artifactId>jacky917-security-resource-server-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

並在消費端 `pom.xml` 增加 repository：

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/jacky917/jacky917-security</url>
    </repository>
</repositories>
```

---

## 7. 常見錯誤排查

- `422 Unprocessable Entity`
  - 檢查 `groupId` 是否為小寫命名空間（2.x 為 `io.github.jacky917`，1.x 為 `com.github.jacky917`）
  - 檢查 `artifactId` 是否全小寫與連字號
  - 檢查是否重複發佈同版本（release 版本不可覆蓋）
- `401 Unauthorized`
  - `settings.xml` 的 `id` 必須與 `distributionManagement.repository.id` 一致（`github`）
  - PAT 權限不足或過期
- `404 Not Found`
  - 發佈 URL 或引用 repository URL 錯誤
  - artifact 尚未成功發佈
- `Could not find artifact com.github.jacky917:jacky917-security-parent:pom`（只有 1.x）
  - 該版本發佈時沒有包含 parent POM。2.x 發佈不含 parent 的獨立 POM，不會發生
- `Could not find artifact org.springframework.boot:spring-boot-starter-parent:pom:3.5.10-SNAPSHOT`（只有 1.0.0）
  - 1.0.0 的 parent 依賴 Spring Boot SNAPSHOT，見 [限制 §16](../resource-server/limitations.md#16-發佈與依賴)
