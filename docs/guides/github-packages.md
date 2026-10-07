# GitHub Packages 發佈與引用指南

本文件說明本專案發佈到 GitHub Packages 的標準配置，並對應常見 `422 Unprocessable Entity` 問題。

---

## 1. 發佈座標（已對齊）

- `groupId`: `com.github.jacky917`
- `artifactId`: `jacky917-security-starter`（以及其他子模組，皆為小寫 + 連字號）
- `version`: 目前已發佈 `1.0.0`（Spring Boot 3.5）；`main` 分支為開發中的 `2.0.0-SNAPSHOT`（Spring Boot 4.1，尚未發佈）。版本由父模組統一管理

> 重點：子模組不自行定義專案版本，全部繼承父模組版本。

---

## 2. 根 POM 的 distributionManagement

已使用以下設定（`pom.xml`）：

```xml
<distributionManagement>
    <repository>
        <id>github</id>
        <name>GitHub Packages</name>
        <url>https://maven.pkg.github.com/jacky917/jacky917-security-starter</url>
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

## 4. Demo 模組不發佈

`demo-resource-server` 與 `demo-authorization-server` 已設定：

```xml
<properties>
    <maven.deploy.skip>true</maven.deploy.skip>
</properties>
```

確保只發佈 Starter 相關模組，不把 demo artifact 推上套件倉庫。

---

## 5. GitHub Actions 發佈流程

實際設定見 [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml)。在 GitHub 上**發佈 Release** 時觸發：

```yaml
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          server-id: github
          server-username: MAVEN_USERNAME
          server-password: GITHUB_TOKEN
      - name: Publish to GitHub Packages
        run: >
          mvn --batch-mode deploy
          -pl .,jacky917-security-starter,jacky917-security-autoconfigure,jacky917-security-annotations
          -DskipTests
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

> [!IMPORTANT]
> `-pl` 中的 `.` 代表根目錄的 `jacky917-security-parent`。三個模組都繼承這個 parent POM，**必須一起發佈**，否則消費端會出現 `Could not find artifact com.github.jacky917:jacky917-security-parent:pom`。

發佈新版本的步驟：

1. 修改根 `pom.xml` 的 `<version>`（子模組會繼承）。
2. 在本機執行 `mvn clean verify` 確認通過。
3. Commit 並 push。
4. 在 GitHub 建立 tag 與 Release，按下 Publish，等待 workflow 完成。

注意：

- GitHub Packages 的正式版本**不可覆蓋**，同一版本號重複發佈會得到 `409 Conflict` 或 `422`。
- workflow 使用 `-DskipTests`，發佈前請確保 CI 或本機測試已通過。
- **發佈出去的版本號由 `pom.xml` 決定，與 Release / tag 名稱無關。** 例如建立 `v1.0.1` Release，但 `pom.xml` 仍是 `1.0.0`，發佈的就是 `1.0.0`（若該版本已存在則會失敗）。請讓 tag 與 `pom.xml` 版本保持一致。

---

## 6. 消費端引用範例

```xml
<dependency>
    <groupId>com.github.jacky917</groupId>
    <artifactId>jacky917-security-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

並在消費端 `pom.xml` 增加 repository：

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/jacky917/jacky917-security-starter</url>
    </repository>
</repositories>
```

---

## 7. 常見錯誤排查

- `422 Unprocessable Entity`
  - 檢查 `groupId` 是否為小寫命名空間（本專案為 `com.github.jacky917`）
  - 檢查 `artifactId` 是否全小寫與連字號
  - 檢查是否重複發佈同版本（release 版本不可覆蓋）
- `401 Unauthorized`
  - `settings.xml` 的 `id` 必須與 `distributionManagement.repository.id` 一致（`github`）
  - PAT 權限不足或過期
- `404 Not Found`
  - 發佈 URL 或引用 repository URL 錯誤
  - artifact 尚未成功發佈
- `Could not find artifact com.github.jacky917:jacky917-security-parent:pom`
  - 該版本發佈時沒有包含 parent POM，見第 5 節
- `Could not find artifact org.springframework.boot:spring-boot-starter-parent:pom:3.5.10-SNAPSHOT`
  - parent POM 依賴 Spring Boot SNAPSHOT，消費端無法存取 Spring Snapshot repository，見 [限制 §16](../resource-server/limitations.md#16-發佈與依賴)
