# E2E 測試指南（Auth Server + Resource Server）

本文件示範如何用 `demo-authorization-server` 簽發 JWT，再呼叫 `demo-resource-server` 受保護端點完成端到端驗證。

## 前置需求

- Java 21
- Maven 3.8+
- 專案根目錄已可執行 `mvn -U clean verify`

## Step 1：安裝本地 SNAPSHOT 依賴

```bash
mvn -U -DskipTests install
```

## Step 2：啟動 Demo Auth Server（Port 8081）

```bash
mvn -pl demo-authorization-server -U spring-boot:run
```

預設監聽：`http://localhost:8081`

## Step 3：啟動 Demo Resource Server（Port 8080）

另開一個終端：

```bash
mvn -pl demo-resource-server -U spring-boot:run
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

```bash
# 200：clipId 符合 demo- 前綴
curl -i "http://localhost:8080/secure/abac/demo-001" \
  -H "Authorization: Bearer $TOKEN"

# 403：clipId 不符合規則
curl -i "http://localhost:8080/secure/abac/private-001" \
  -H "Authorization: Bearer $TOKEN"
```

## 常見問題排查

- `401 invalid token`：確認兩個 demo 模組使用同一份 `demo-hs256.jwk.json`。
- `Could not find artifact ... 0.0.1-SNAPSHOT`：先執行 `mvn -U -DskipTests install`。
- `連線被拒絕`：確認兩個服務都已啟動，且埠號為 8081 / 8080。

