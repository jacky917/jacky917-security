# 授權模型 (Authorization Model)

本 Starter 支援一個混合式授權模型，結合了角色基礎存取控制（RBAC）、權限（Permissions）以及屬性基礎存取控制（ABAC）的擴展點。

## 核心概念

1.  **角色 (Role-Based Access Control, RBAC)**
    - **定義**：代表一組使用者或職責，例如 `ADMIN`, `USER`, `GUEST`。
    - **來源**：JWT `roles` claim。
    - **Spring Security 表達式**：`@PreAuthorize("hasRole('ADMIN')")` 或 `@PreAuthorize("hasAnyRole('ADMIN', 'USER')")`。
    - **用途**：適用於粗顆粒度的權限控制。

2.  **權限 (Permissions)**
    - **定義**：代表對特定資源的特定操作，例如 `product:read`, `product:write`。
    - **來源**：JWT `permissions` claim。
    - **Spring Security 表達式**：`@PreAuthorize("hasAuthority('product:read')")`。
    - **用途**：適用於細顆粒度的權限控制，實現資源級別的授權。

3.  **範疇 (Scope)**
    - **定義**：通常用於 OAuth2 流程，代表客戶端應用被授予的權限範圍，例如 `profile.read`。
    - **來源**：JWT `scope` 或 `scp` claim。
    - **Spring Security 表達式**：`@PreAuthorize("hasAuthority('SCOPE_profile.read')")`。
    - **用途**：限制第三方應用的存取權限。

4.  **屬性基礎存取控制 (Attribute-Based Access Control, ABAC)**
    - **定義**：一種更動態的授權模型，它基於使用者屬性、資源屬性與環境條件來做決策。例如：「只有當文件的 `ownerId` 與當前使用者的 `userId` 相同時，才允許編輯」。
    - **實現方式**：透過自訂 Spring Security 表達式來實現。例如，`@PreAuthorize("@permissionService.canEditDocument(#documentId)")`。
    - **擴展點**：本 Starter 提供與 `@EnableMethodSecurity` 的無縫整合，開發者可以輕易地註冊自訂的 `MethodSecurityExpressionHandler` 或權限評估服務 Bean。

## 權限表達式邏輯 (AND / OR)

Spring Security 的表達式語言（SpEL）提供了強大的邏輯組合能力。

### 範例 A: AND（`@RequireAll`）

要求使用者必須**同時**擁有 `ROLE_ADMIN` 與 `PERM_product:write`。

```java
@RequireAll("ROLE_ADMIN|PERM_product:write")
@PostMapping("/products")
public ResponseEntity<Void> createProduct(@RequestBody Product product) {
    return ResponseEntity.status(HttpStatus.CREATED).build();
}
```

### 範例 B: OR（`@RequireAny`）

要求使用者只要擁有 `ROLE_CONTENT_MANAGER` 或 `PERM_article:publish` 任一即可。

```java
@RequireAny("ROLE_CONTENT_MANAGER|PERM_article:publish")
@PostMapping("/articles/{id}/publish")
public ResponseEntity<Void> publishArticle(@PathVariable String id) {
    return ResponseEntity.ok().build();
}
```

### 範例 C: 單一角色/權限/Scope（`@RequireRole` / `@RequirePerm` / `@RequireScope`）

這三個註解用於最常見的單一條件授權，參數不需帶前綴。

```java
@RequireRole("ADMIN")              // 檢查 ROLE_ADMIN
@RequirePerm("order:read")         // 檢查 PERM_order:read
@RequireScope("profile.read")      // 檢查 SCOPE_profile.read
```

### 範例 D: 與 ABAC 結合

當需要「權限 + 業務屬性」混合判斷時，建議在自訂註解外再補一層 `@PreAuthorize`：

```java
@RequirePerm("order:read")
@PreAuthorize("@orderSecurity.isOwner(authentication, #orderId)")
@GetMapping("/orders/{orderId}")
public ResponseEntity<Order> getOrderById(@PathVariable String orderId) {
    Order order = orderService.findById(orderId);
    return ResponseEntity.ok(order);
}
```

這種寫法能保留註解式 RBAC/Permission 的可讀性，同時整合 ABAC 的動態條件。
