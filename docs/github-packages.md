# GitHub Packages 發佈與引用指南

本文件說明本專案發佈到 GitHub Packages 的標準配置，並對應常見 `422 Unprocessable Entity` 問題。

---

## 1. 發佈座標（已對齊）

- `groupId`: `com.github.jacky917`
- `artifactId`: `jacky917-security-starter`（以及其他子模組，皆為小寫 + 連字號）
- `version`: `1.0.0`（由父模組統一管理）

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

## 5. GitHub Actions 發佈範例

```yaml
name: Publish package to GitHub Packages

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          server-id: github
      - name: Publish
        run: mvn -B -U deploy -pl jacky917-security-annotations,jacky917-security-autoconfigure,jacky917-security-starter -am
```

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
