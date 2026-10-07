# 授權模型（Authorization Model）

本 Starter 支援混合式授權模型：角色（RBAC）、權限（Permission）、OAuth 2.0 範疇（Scope），以及屬性型存取控制（ABAC）的擴充點。

前三者來自 JWT claims，在驗證時一次轉成 authority；ABAC 則在方法呼叫時，由你的程式依資源資料動態判斷。

---

## 概念與 authority 對照

| 模型 | 典型用途 | JWT claim | authority | 推薦寫法 |
|---|---|---|---|---|
| 角色（RBAC） | 粗粒度身分：`ADMIN`、`USER` | `roles` | `ROLE_ADMIN` | `@RequireRole("ADMIN")` |
| 權限（Permission） | 細粒度操作：`order:read`、`order:write` | `permissions` | `PERM_order:read` | `@RequirePerm("order:read")` |
| 範疇（Scope） | 使用者授權給**客戶端應用**的範圍 | `scope` / `scp` | `SCOPE_profile.read` | `@RequireScope("profile.read")` |
| ABAC | 依資源屬性判斷：「只有擁有者能修改」 | — | — | `@PreAuthorize("@bean.method(...)")` |

### 角色 vs 權限 vs Scope 怎麼選？

- **角色**描述「你是誰」。適合規則簡單、角色數量少的系統。缺點是角色和功能綁死，新增功能時常要修改多處的角色清單。
- **權限**描述「你能做什麼」。建議 API 層一律以權限判斷，再由 Authorization Server 決定每個角色擁有哪些權限。這樣調整角色權限時，不需要修改或重新部署 API。
- **Scope** 描述「使用者允許這個 App 代表他做什麼」。適用於第三方應用或多個客戶端共用 API 的情境。Scope 與使用者本身的權限是兩回事，常見做法是兩者都檢查。

權限命名建議使用 `資源:動作`，例如 `order:read`、`order:write`、`report:export`。

---

## 單一條件

```java
@RequireRole("ADMIN")              // 檢查 ROLE_ADMIN
@RequirePerm("order:read")         // 檢查 PERM_order:read
@RequireScope("profile.read")      // 檢查 SCOPE_profile.read
```

參數不帶前綴，註解會自動加上。也可以使用 Spring Security 原生寫法：

```java
@PreAuthorize("hasRole('ADMIN')")                  // hasRole 會自動補 ROLE_
@PreAuthorize("hasAuthority('PERM_order:read')")   // hasAuthority 要寫完整名稱
@PreAuthorize("hasAuthority('SCOPE_profile.read')")
```

> [!NOTE]
> `hasAuthority('order:read')`（沒有 `PERM_` 前綴）**永遠不會通過**，因為 Starter 映射出的 authority 是 `PERM_order:read`。

---

## AND / OR

### AND：`@RequireAll`

使用者必須**同時**擁有 `ROLE_ADMIN` 與 `PERM_product:write`：

```java
@RequireAll("ROLE_ADMIN|PERM_product:write")
@PostMapping("/products")
public ResponseEntity<Void> createProduct(@RequestBody Product product) { ... }
```

### OR：`@RequireAny`

使用者擁有 `ROLE_CONTENT_MANAGER` **或** `PERM_article:publish` 任一即可：

```java
@RequireAny("ROLE_CONTENT_MANAGER|PERM_article:publish")
@PostMapping("/articles/{id}/publish")
public ResponseEntity<Void> publishArticle(@PathVariable String id) { ... }
```

規則：

- 參數使用**含前綴**的完整 authority 名稱，以 `|` 分隔，前後空白會被忽略。
- 參數中沒有任何有效項目時（例如 `""`、`"|"`），一律拒絕。
- 參數不可包含單引號 `'`。

### 更複雜的組合

「(A 且 B) 或 C」這類巢狀邏輯無法用 `@RequireAny` / `@RequireAll` 表達，請直接寫 SpEL：

```java
@PreAuthorize("(hasRole('EDITOR') and hasAuthority('PERM_article:write')) or hasRole('ADMIN')")
```

---

## ABAC（資源屬性授權）

當授權結果取決於**資料本身**（例如擁有者、所屬部門、文件狀態）時，authority 無法表達，需要在方法呼叫時查詢資料判斷。

### 寫法

1. 建立一個 Bean，提供回傳 `boolean` 的判斷方法：

   ```java
   @Component("orderSecurity")
   public class OrderSecurity {

       private final OrderRepository orders;

       public OrderSecurity(OrderRepository orders) {
           this.orders = orders;
       }

       public boolean isOwner(Authentication authentication, String orderId) {
           if (authentication == null || orderId == null) {
               return false;
           }
           return orders.findById(orderId)
                   .map(order -> order.getOwnerId().equals(authentication.getName()))
                   .orElse(false);
       }
   }
   ```

2. 在 `@PreAuthorize` 中**同時**寫出權限與 ABAC 條件：

   ```java
   @PreAuthorize("hasAuthority('PERM_order:read') and @orderSecurity.isOwner(authentication, #orderId)")
   @GetMapping("/orders/{orderId}")
   public Order getOrder(@PathVariable String orderId) { ... }
   ```

> [!CAUTION]
> **不可以**把 `@RequirePerm` 和 `@PreAuthorize` 疊在同一個方法上：
>
> ```java
> @RequirePerm("order:read")                                         // ❌
> @PreAuthorize("@orderSecurity.isOwner(authentication, #orderId)")  // ❌
> ```
>
> 兩者底層都是 `@PreAuthorize`，會在請求進來時拋出 `AnnotationConfigurationException`（HTTP 500）。見 [限制 §1](limitations.md#1-同一個方法只能有一個授權註解)。

### 設計建議

- **預設拒絕**：參數為 `null`、資料不存在、任何例外，都回傳 `false`。
- **先檢查權限再查資料**：把 `hasAuthority(...)` 寫在 `and` 的左邊。SpEL 的 `and` 會短路，沒有權限的請求就不會查詢資料庫。
- **以 `sub` 比對擁有者**：`authentication.getName()` 是 JWT 的 `sub`，資料庫中的 owner 欄位應存同一個識別碼。不要用 email、暱稱等可能變動的值。
- **注意查詢成本**：判斷方法每次請求都會執行，若需要查資料庫，Controller 往往還會再查一次。可以考慮改用 `@PostAuthorize("returnObject.ownerId == authentication.name")`，在取得資料後再判斷，只查一次。
- **集合結果**：列表 API 不適合逐筆用 `@PreAuthorize` 判斷，應在查詢條件中直接加上 `WHERE owner_id = :currentUser`。

### Demo 範例

`demo-resource-server` 以 Clip 為例實作了 ABAC：

- [`AuthzService`](../examples/example-resource-server/src/main/java/jacky917/demo/resourceserver/authz/AuthzService.java)：判斷介面
- [`DemoAuthzConfiguration`](../examples/example-resource-server/src/main/java/jacky917/demo/resourceserver/authz/DemoAuthzConfiguration.java)：以 `clip.ownerId == JWT sub` 判斷，找不到資料時拒絕
- [`DemoSecureController#abac`](../examples/example-resource-server/src/main/java/jacky917/demo/resourceserver/controller/DemoSecureController.java)：`@PreAuthorize("hasAuthority('PERM_clip:read') and @authzService.canAccessClip(authentication, #clipId)")`

---

## 類別層級的註解

授權註解可以放在類別上，套用到所有方法：

```java
@RestController
@RequireRole("ADMIN")
class AdminController { ... }
```

> [!WARNING]
> 方法上若另有授權註解，類別上的註解會被**忽略**，兩者不會合併。見 [限制 §2](limitations.md#2-類別與方法的註解不會合併)。
