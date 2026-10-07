# E2E 測試指南（Auth Server + Resource Server）

本文件示範如何用 `demo-authorization-server` 簽發 JWT，再呼叫 `demo-resource-server` 受保護端點完成端到端驗證。

## 前置需求

- JDK 21 以上
- Maven 3.8 以上
- Docker（或本機 MySQL 8.4）：`demo-resource-server` 執行時需要資料庫
- 專案根目錄已可執行 `mvn clean verify`

## Step 0：啟動 MySQL

`demo-resource-server` 預設連線 `localhost:3307/demo_db`，帳密 `root` / `root`（見 `demo-resource-server/src/main/resources/application.yml`）。

```bash
docker run -d --name jacky917-demo-mysql -p 3307:3306 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=demo_db mysql:8.4
```

資料表由 Hibernate 自動建立（`ddl-auto: update`），啟動時 `ClipDemoDataInitializer` 會寫入兩筆資料：

| clipId | owner |
|---|---|
| `demo-001` | `alice` |
| `private-001` | `bob` |

## Step 1：安裝本地模組

```bash
mvn -DskipTests install
```

## Step 2：啟動 Demo Auth Server（Port 8081）

```bash
mvn -pl demo-authorization-server spring-boot:run
```

預設監聽：`http://localhost:8081`

## Step 3：啟動 Demo Resource Server（Port 8080）

另開一個終端：

```bash
mvn -pl demo-resource-server spring-boot:run
```

預設監聽：`http://localhost:8080`

## Step 4：向 Auth Server 取得 Access Token

```bash
TOKEN=$(curl -s -X POST "http://localhost:8081/oauth2/token" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"alice",
    "password":"password",
    "roles":["A"],
    "permissions":["bb","clip:read"],
    "scp":["profile.read"],
    "sid":"sid-e2e"
  }' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')
```

快速確認：

```bash
echo "$TOKEN" | wc -c
```

若長度大於 100，通常代表 token 已成功取得。

Demo Auth Server 的規則：

- 密碼固定為 `password`，任何 `username` 都可登入；`username` 會成為 Token 的 `sub`。
- `roles` / `permissions` / `scp` / `sid` / `expiresInSeconds` 皆可省略，省略時預設為 `["A"]`、`["bb","clip:read"]`、`["profile.read"]`、`sid-demo-auth`、600 秒。
- Token 以 HS256 簽署，`iss` 為 `jacky917-demo-auth-server`，`aud` 為 `demo-resource-server`。

> [!CAUTION]
> Demo Auth Server 允許呼叫端自行指定任意角色與權限，**僅供本地測試**，絕對不可部署到任何可對外連線的環境。

## Step 5：呼叫 Resource Server 端點

### 5.1 匿名端點（200）

```bash
curl -i "http://localhost:8080/public/ping"
```

### 5.2 未帶 Token（401）

```bash
curl -i "http://localhost:8080/secure/me"
```

### 5.3 帶 Token（200）

```bash
curl -i "http://localhost:8080/secure/me" \
  -H "Authorization: Bearer $TOKEN"
```

### 5.4 AND 端點（200）

```bash
curl -i "http://localhost:8080/secure/and" \
  -H "Authorization: Bearer $TOKEN"
```

### 5.5 OR 端點（200）

```bash
curl -i "http://localhost:8080/secure/or" \
  -H "Authorization: Bearer $TOKEN"
```

### 5.6 ABAC 端點（200 / 403）

規則：需要 `PERM_clip:read`，且資料庫中 `clip.ownerId` 必須等於 Token 的 `sub`。以下假設 Token 是用 `alice` 取得的。

```bash
# 200：demo-001 的 owner 是 alice
curl -i "http://localhost:8080/secure/abac/demo-001" \
  -H "Authorization: Bearer $TOKEN"

# 403：private-001 的 owner 是 bob
curl -i "http://localhost:8080/secure/abac/private-001" \
  -H "Authorization: Bearer $TOKEN"

# 403：不存在的 clip 一律拒絕
curl -i "http://localhost:8080/secure/abac/not-exist" \
  -H "Authorization: Bearer $TOKEN"
```

### 5.7 權限不足（403）

取一個沒有 `ROLE_A` 與 `PERM_bb` 的 Token，呼叫 OR 端點：

```bash
TOKEN_NOPERM=$(curl -s -X POST "http://localhost:8081/oauth2/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"carol","password":"password","roles":["GUEST"],"permissions":["none"]}' \
  | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')

curl -i "http://localhost:8080/secure/or" -H "Authorization: Bearer $TOKEN_NOPERM"
```

預期回應 `403`，內容為 `{"status":403,"errorCode":"Forbidden",...}`。

### 5.8 無效 Token（401）

```bash
curl -i "http://localhost:8080/secure/me" -H "Authorization: Bearer not-a-jwt"
```

預期回應 `401`，`WWW-Authenticate` 標頭包含 `error="invalid_token"`。

## 常見問題排查

- `401 invalid token`：確認兩個 demo 模組的 `demo-hs256.jwk.json` 內容相同；Token 是否已過期（預設 10 分鐘）。
- `Could not find artifact com.github.jacky917:...`：先執行 `mvn -DskipTests install`。
- `Communications link failure`（Resource Server 啟動失敗）：MySQL 未啟動，或埠號不是 3307。
- `連線被拒絕`：確認兩個服務都已啟動，且埠號為 8081 / 8080。
- 其他問題見 [疑難排解](../resource-server/troubleshooting.md)。

