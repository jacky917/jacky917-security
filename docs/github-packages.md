# GitHub Packages 發佈與引用指南

本文件旨在提供一個完整的指南，說明如何將 Maven 專案（如 `jacky917-security-starter`）發佈到個人的私有 GitHub Packages，並在其他專案中引用。

**假設前提**：
-   你的 GitHub 用戶名為 `YOUR_USERNAME`。
-   你的 GitHub Repository 名稱為 `YOUR_REPOSITORY`。
-   你已經產生了一個具有 `write:packages` 和 `read:packages` 權限的 Personal Access Token (PAT)。

---

## 1. 設定專案 `pom.xml`

你需要在 `pom.xml` 中加入 `distributionManagement` 區塊，告訴 Maven 當執行 `deploy` 命令時，要把產出物上傳到哪裡。

```xml
<!-- 放在專案根 pom.xml 的 <project> 標籤內 -->
<distributionManagement>
    <repository>
        <id>github</id>
        <name>GitHub YOUR_USERNAME Apache Maven Packages</name>
        <url>https://maven.pkg.github.com/YOUR_USERNAME/YOUR_REPOSITORY</url>
    </repository>
</distributionManagement>
```

-   **`<id>github</id>`**：這個 ID 非常重要，它必須與 `settings.xml` 中的 `<server>` ID 完全匹配。
-   **`<url>`**：將 `YOUR_USERNAME` 和 `YOUR_REPOSITORY` 替換為你自己的資訊。

---

## 2. 設定本地 Maven `~/.m2/settings.xml`

為了讓 Maven 能夠通過 GitHub 的認證，你需要在本地的 `settings.xml` 檔案中配置你的 GitHub 用戶名和 Personal Access Token (PAT)。

**絕對不要將 Token 硬編碼在 `pom.xml` 中！**

```xml
<!-- ~/.m2/settings.xml -->
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              https://maven.apache.org/xsd/settings-1.0.0.xsd">
    <servers>
        <server>
            <id>github</id>
            <username>YOUR_USERNAME</username>
            <password>YOUR_PERSONAL_ACCESS_TOKEN</password>
        </server>
    </servers>
</settings>
```
-   **`<id>github</id>`**：必須與 `pom.xml` 中的 `distributionManagement.repository.id` 相同。
-   **`<username>`**：你的 GitHub 用戶名。
-   **`<password>`**：你的 Personal Access Token (PAT)。

---

## 3. 使用 GitHub Actions 自動發佈

在手動驗證發佈流程可行後，強烈建議使用 GitHub Actions 來自動化此過程。

在你的專案根目錄下建立 `.github/workflows/maven-publish.yml`：

```yaml
# .github/workflows/maven-publish.yml
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
          server-id: github # Value of the distributionManagement repo id from pom.xml
          settings-path: ${{ github.workspace }} # location for settings.xml

      - name: Publish package
        run: mvn -B deploy --file pom.xml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
**工作流程解釋**：
-   `on: release: types: [created]`: 這個 workflow 會在每次你建立一個新的 GitHub Release 時觸發。
-   `permissions`: 授予 job 寫入 GitHub Packages 的權限。
-   `actions/setup-java@v4`: 這個 action 會自動幫你配置好 `settings.xml`，你無需手動建立。它會使用 job 內建的 `GITHUB_TOKEN`，所以你也不需要自己去設定 secret。
-   `mvn -B deploy`: `-B` 是批次模式（batch mode），`deploy` 命令會讀取 `pom.xml` 中的 `distributionManagement` 設定，並將套件發佈。

---

## 4. 在其他專案中引用

要在另一個 Maven 專案中引用你發佈的 Starter，消費者也需要在他們的 `pom.xml` 和 `settings.xml` 中進行設定。

### 消費者的 `pom.xml`

```xml
<dependencies>
    <dependency>
        <groupId>jacky917</groupId>
        <artifactId>jacky917-security-starter</artifactId>
        <version>1.0.0-SNAPSHOT</version> <!-- 替換成你發佈的版本 -->
    </dependency>
</dependencies>

<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/YOUR_USERNAME/YOUR_REPOSITORY</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>
```
-   **`<repositories>`**: 告訴 Maven 除了 Maven Central 之外，還要去哪裡尋找依賴。

### 消費者的 `~/.m2/settings.xml`

消費者也需要在他們的 `settings.xml` 中配置一個具有 `read:packages` 權限的 PAT，格式與發佈者完全相同。

---

## 常見錯誤排查

-   **`401 Unauthorized`**:
    -   檢查你的 PAT 是否有正確的 `write:packages` (發佈時) 或 `read:packages` (引用時) 權限。
    -   確認 `settings.xml` 中的 `<id>` 與 `pom.xml` 中的 `<id>` 完全一致。
    -   確認 PAT 沒有過期。

-   **`404 Not Found`**:
    -   當引用依賴時出現，檢查 `pom.xml` 中的 `<repository>` URL 是否正確（`YOUR_USERNAME` 和 `YOUR_REPOSITORY` 是否正確）。
    -   確認你要引用的套件版本確實已經成功發佈到 GitHub Packages。

-   **`500 Internal Server Error`**:
    -   偶爾可能是 GitHub Packages 的暫時性問題。
    -   也可能是你的 `pom.xml` 或 artifact 有問題。嘗試在本機執行 `mvn clean install` 確保一切正常。
