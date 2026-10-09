package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.admin.AdminAuditService;
import jacky917.security.authorizationserver.admin.AdminAuditTarget;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 管理 API（第 3、4 階段設計 §4）：Bearer token 的驗證與 {@code as:*} 權限、稽核查詢，以及之後各工作的管理端點。
 */
abstract class AbstractAdminApiIntegrationTest extends AbstractFlowIntegrationTest {

    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    AdminAuditService adminAudit;

    @Test
    @DisplayName("沒有 token：401；token 的 aud 不是管理 API：401；沒有對應權限：403（T-ADMIN-01）")
    void requiresAnAdminToken() throws Exception {
        mockMvc.perform(get("/admin/api/audit/logins")).andExpect(status().isUnauthorized());
        String otherAudience = mint(Map.of("aud", List.of("order-api"), "permissions", List.of("as:audit:read"),
                "asid", "a"));
        mockMvc.perform(get("/admin/api/audit/logins").header(HttpHeaders.AUTHORIZATION, "Bearer " + otherAudience))
                .andExpect(status().isUnauthorized());
        String plainUser = userToken("plain-admin-caller");
        call(get("/admin/api/audit/logins"), plainUser).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("AS_SUPPORT 可以讀取稽核；回傳新的在前、可分頁與篩選（T-ADMIN-02 的讀取部分）")
    void supportReadsTheAudit() throws Exception {
        String supportId = createUser("support-reader", null, "AS_SUPPORT");
        String token = userToken("support-reader");
        JsonNode page = json(call(get("/admin/api/audit/logins").param("userId", supportId).param("size", "1"),
                token).andExpect(status().isOk()));
        assertThat(page.get("total").asLong()).isGreaterThanOrEqualTo(1);
        assertThat(page.get("items")).hasSize(1);
        assertThat(page.get("items").get(0).get("type").asString()).isEqualTo("LOGIN");
        assertThat(page.get("items").get(0).get("userId").asString()).isEqualTo(supportId);

        JsonNode none = json(call(get("/admin/api/audit/logins").param("userId", supportId)
                .param("from", clock.instant().plusSeconds(3600).toString()), token).andExpect(status().isOk()));
        assertThat(none.get("total").asLong()).isZero();
    }

    @Test
    @DisplayName("client_credentials 的 token 以 as: 開頭的 scope 授權（T-ADMIN-03）")
    void clientCredentialsUseScopes() throws Exception {
        String token = json(mockMvc.perform(post("/oauth2/token").with(httpBasic("admin-sync", "sync-secret"))
                .param("grant_type", "client_credentials").param("scope", "as:audit:read"))
                .andExpect(status().isOk())).get("access_token").asString();
        call(get("/admin/api/audit/admin"), token).andExpect(status().isOk());
        // 沒有 as:role:read
        call(get("/admin/api/roles"), token).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("管理稽核：記錄對象與快照；可依對象篩選（操作者見 recordsTheOperator）")
    void recordsAdminActions() throws Exception {
        createUser("audit-admin", null, "AS_ADMIN");
        String token = userToken("audit-admin");
        adminAudit.record("TEST_ACTION", AdminAuditTarget.API_RESOURCE, "order-api", null, Map.of("name", "Orders"));
        JsonNode page = json(call(get("/admin/api/audit/admin").param("targetType", "API_RESOURCE")
                .param("targetId", "order-api"), token).andExpect(status().isOk()));
        assertThat(page.get("items")).hasSize(1);
        JsonNode entry = page.get("items").get(0);
        assertThat(entry.get("action").asString()).isEqualTo("TEST_ACTION");
        assertThat(JSON.readTree(entry.get("after").asString()).get("name").asString()).isEqualTo("Orders");
    }

    @Test
    @DisplayName("分頁參數錯誤：400，回傳 Problem Details 與欄位錯誤")
    void invalidPagesAreProblems() throws Exception {
        createUser("paging-admin", null, "AS_ADMIN");
        JsonNode problem = json(call(get("/admin/api/audit/logins").param("size", "0"), userToken("paging-admin"))
                .andExpect(status().isBadRequest()));
        assertThat(problem.get("status").asInt()).isEqualTo(400);
        assertThat(problem.get("errors").get("size").asString()).contains("between 1 and 200");
    }

    @Test
    @DisplayName("資料庫約束與程式一致：每一種稽核事件與管理稽核對象都可以寫入")
    void everyAuditValueIsAllowed() {
        for (LoginAuditEventType type : LoginAuditEventType.values()) {
            jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, success) VALUES (:at, :type, :ok)")
                    .param("at", Timestamp.from(Instant.now())).param("type", type.name()).param("ok", true).update();
        }
        for (AdminAuditTarget target : AdminAuditTarget.values()) {
            jdbc.sql("INSERT INTO admin_audit_log (occurred_at, action, target_type) VALUES (:at, 'TEST', :target)")
                    .param("at", Timestamp.from(Instant.now())).param("target", target.name()).update();
        }
        assertThat(jdbc.sql("SELECT password_change_required FROM app_user WHERE username = 'admin'")
                .query(Boolean.class).single()).isNotNull();
    }

    // ---- 工作 19：使用者 ----

    @Test
    @DisplayName("建立使用者並指派角色；使用者登入後的 token 帶有該角色與權限；稽核快照不含密碼雜湊（T-ADMIN-04、06）")
    void createsUsersWithRoles() throws Exception {
        String admin = adminToken("creator-admin");
        JsonNode created = json(send(postJson("/admin/api/users"), admin, Map.of("username", "new-support",
                "email", "new-support@example.com", "emailVerified", true, "password", PASSWORD,
                "passwordChangeRequired", false, "displayName", "New Support", "roles", List.of("AS_SUPPORT")))
                .andExpect(status().isCreated()));
        String userId = created.get("user").get("id").asString();
        assertThat(created.get("roles")).extracting(role -> role.get("role").asString())
                .containsExactlyInAnyOrder("USER", "AS_SUPPORT");
        assertThat(created.get("user").get("passwordSet").asBoolean()).isTrue();
        assertThat(created.get("user").has("passwordHash")).isFalse();

        JsonNode access = JSON.readTree(java.util.Base64.getUrlDecoder().decode(
                userToken("new-support").split("\\.")[1]));
        assertThat(access.get("roles")).extracting(JsonNode::asString).contains("AS_SUPPORT");
        assertThat(access.get("permissions")).extracting(JsonNode::asString).contains("as:user:read");

        String after = jdbc.sql("SELECT after_value FROM admin_audit_log WHERE action = 'USER_CREATED' AND target_id = :id")
                .param("id", userId).query(String.class).single();
        assertThat(after).contains("new-support").doesNotContain("password_hash").doesNotContain("{bcrypt}");
    }

    @Test
    @DisplayName("AS_SUPPORT 可以讀取使用者，不能建立使用者（T-ADMIN-02）")
    void supportCannotWrite() throws Exception {
        createUser("support-writer", null, "AS_SUPPORT");
        String token = userToken("support-writer");
        call(getJson("/admin/api/users"), token).andExpect(status().isOk());
        send(postJson("/admin/api/users"), token, Map.of("username", "nobody-new")).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("搜尋：依帳號、Email 或顯示名稱部分比對（不分大小寫），可依狀態篩選；% 與 _ 視為一般字元")
    void searchesUsers() throws Exception {
        String admin = adminToken("search-admin");
        createUser("Findable_One", "Display Findable");
        String disabled = createUser("findable-two", null);
        jdbc.sql("UPDATE app_user SET status = 'DISABLED' WHERE id = :id").param("id", disabled).update();
        JsonNode all = json(call(getJson("/admin/api/users").param("query", "FINDABLE"), admin)
                .andExpect(status().isOk()));
        assertThat(all.get("items")).extracting(user -> user.get("username").asString())
                .containsExactlyInAnyOrder("Findable_One", "findable-two");
        JsonNode onlyDisabled = json(call(getJson("/admin/api/users").param("query", "findable")
                .param("status", "DISABLED"), admin));
        assertThat(onlyDisabled.get("items")).extracting(user -> user.get("id").asString()).containsExactly(disabled);
        JsonNode underscore = json(call(getJson("/admin/api/users").param("query", "e_o"), admin));
        assertThat(underscore.get("items")).extracting(user -> user.get("username").asString())
                .containsExactly("Findable_One");
    }

    @Test
    @DisplayName("停用使用者：撤銷所有登入 Session、Refresh Token 失效、無法登入；恢復後可再登入（T-ADMIN-05）")
    void disablingRevokesSessions() throws Exception {
        String admin = adminToken("disable-admin");
        String userId = createUser("to-disable", null);
        LoggedIn session = logInAndExchangeCode("to-disable");
        send(patchJson("/admin/api/users/" + userId), admin, Map.of("status", "DISABLED")).andExpect(status().isOk());
        assertSession(session.asid(), "REVOKED", "USER_DISABLED");
        assertRefreshRefused(session);
        send(patchJson("/admin/api/users/" + userId), admin, Map.of("status", "ACTIVE")).andExpect(status().isOk());
        assertThat(logInAndExchangeCode("to-disable").asid()).isNotNull();
    }

    @Test
    @DisplayName("更新欄位：只改有出現的欄位；Email 變更後視為未驗證；不明的欄位 400；重複的 Email 409")
    void updatesFields() throws Exception {
        String admin = adminToken("update-admin");
        String userId = users.createUser(new jacky917.security.authorizationserver.user.NewUser("patched", "old@example.com",
                true, PASSWORD, "Old Name", java.util.Set.of())).id();
        users.createUser(new jacky917.security.authorizationserver.user.NewUser(null, "taken@example.com", true, null,
                null, java.util.Set.of()));
        JsonNode updated = json(send(patchJson("/admin/api/users/" + userId), admin,
                Map.of("email", "new@example.com")).andExpect(status().isOk())).get("user");
        assertThat(updated.get("email").asString()).isEqualTo("new@example.com");
        assertThat(updated.get("emailVerified").asBoolean()).isFalse();
        assertThat(updated.get("displayName").asString()).isEqualTo("Old Name");
        send(patchJson("/admin/api/users/" + userId), admin, Map.of("nickname", "x")).andExpect(status().isBadRequest());
        send(patchJson("/admin/api/users/" + userId), admin, Map.of("email", "TAKEN@example.com"))
                .andExpect(status().isConflict());
        call(getJson("/admin/api/users/no-such-user"), admin).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("設定密碼：撤銷所有登入 Session，舊密碼失效，下次登入必須變更；解除暫時鎖定")
    void setsPasswordsAndUnlocks() throws Exception {
        String admin = adminToken("password-admin");
        String userId = createUser("password-target", null);
        LoggedIn session = logInAndExchangeCode("password-target");
        send(putJson("/admin/api/users/" + userId + "/password"), admin, Map.of("password", "short"))
                .andExpect(status().isBadRequest());
        send(putJson("/admin/api/users/" + userId + "/password"), admin,
                Map.of("password", "a brand new password")).andExpect(status().isNoContent());
        assertSession(session.asid(), "REVOKED", "PASSWORD_CHANGED");
        assertThat(json(call(getJson("/admin/api/users/" + userId), admin)).get("user")
                .get("passwordChangeRequired").asBoolean()).isTrue();

        jdbc.sql("UPDATE app_user SET locked_until = :until, failed_login_count = 3 WHERE id = :id")
                .param("until", Timestamp.from(clock.instant().plusSeconds(600))).param("id", userId).update();
        JsonNode unlocked = json(call(postJson("/admin/api/users/" + userId + "/unlock"), admin)
                .andExpect(status().isOk())).get("user");
        assertThat(unlocked.get("lockedUntil").isNull()).isTrue();
        assertThat(unlocked.get("failedLoginCount").asInt()).isZero();
    }

    @Test
    @DisplayName("角色：指派（可設定到期）與移除；不存在的角色 404；過去的到期時間 400")
    void assignsAndRemovesRoles() throws Exception {
        String admin = adminToken("role-admin");
        String userId = createUser("role-target", null);
        // SQLite 只保存到毫秒
        Instant expires = clock.instant().plusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        JsonNode user = json(send(putJson("/admin/api/users/" + userId + "/roles/AS_SUPPORT"), admin,
                Map.of("expiresAt", expires.toString())).andExpect(status().isOk()));
        assertThat(user.get("roles")).anySatisfy(role -> {
            assertThat(role.get("role").asString()).isEqualTo("AS_SUPPORT");
            assertThat(Instant.parse(role.get("expiresAt").asString())).isEqualTo(expires);
        });
        send(putJson("/admin/api/users/" + userId + "/roles/NO_SUCH_ROLE"), admin, Map.of())
                .andExpect(status().isNotFound());
        send(putJson("/admin/api/users/" + userId + "/roles/AS_SUPPORT"), admin,
                Map.of("expiresAt", clock.instant().minusSeconds(1).toString())).andExpect(status().isBadRequest());
        JsonNode removed = json(call(deleteJson("/admin/api/users/" + userId + "/roles/AS_SUPPORT"), admin)
                .andExpect(status().isOk()));
        assertThat(removed.get("roles")).extracting(role -> role.get("role").asString()).containsExactly("USER");
    }

    @Test
    @DisplayName("不能停用或刪除自己，也不能移除自己最後一個可以管理使用者的角色（T-ADMIN-07 的一部分）")
    void protectsTheCaller() throws Exception {
        String adminId = createUser("self-admin", null, "AS_ADMIN");
        String admin = userToken("self-admin");
        send(patchJson("/admin/api/users/" + adminId), admin, Map.of("status", "DISABLED"))
                .andExpect(status().isBadRequest());
        call(deleteJson("/admin/api/users/" + adminId), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/users/" + adminId + "/roles/AS_ADMIN"), admin).andExpect(status().isConflict());
        assertThat(json(call(getJson("/admin/api/users/" + adminId), admin)).get("roles"))
                .extracting(role -> role.get("role").asString()).contains("AS_ADMIN");
    }

    @Test
    @DisplayName("登入 Session：列出、撤銷單一與全部；刪除使用者時撤銷全部")
    void managesSessions() throws Exception {
        String admin = adminToken("session-admin");
        String userId = createUser("session-target", null);
        LoggedIn first = logInAndExchangeCode("session-target");
        LoggedIn second = logInAndExchangeCode("session-target");
        JsonNode list = json(call(getJson("/admin/api/users/" + userId + "/sessions"), admin)
                .andExpect(status().isOk()));
        assertThat(list).extracting(session -> session.get("sessionId").asString())
                .containsExactlyInAnyOrder(first.asid(), second.asid());
        call(deleteJson("/admin/api/sessions/" + first.asid()), admin).andExpect(status().isNoContent());
        assertSession(first.asid(), "REVOKED", "ADMIN");
        call(deleteJson("/admin/api/sessions/no-such-session"), admin).andExpect(status().isNotFound());
        JsonNode revoked = json(call(deleteJson("/admin/api/users/" + userId + "/sessions"), admin)
                .andExpect(status().isOk()));
        assertThat(revoked.get("revoked").asInt()).isEqualTo(1);
        assertSession(second.asid(), "REVOKED", "ADMIN");

        LoggedIn third = logInAndExchangeCode("session-target");
        call(deleteJson("/admin/api/users/" + userId), admin).andExpect(status().isNoContent());
        assertSession(third.asid(), "REVOKED", "USER_DISABLED");
        assertThat(json(call(getJson("/admin/api/users/" + userId), admin)).get("user").get("status").asString())
                .isEqualTo("DELETED");
    }

    // ---- 工作 20：角色與權限 ----

    @Test
    @DisplayName("業務權限與角色：建立權限與角色、指派給使用者；使用者的 token 帶有它們；稽核記錄建立")
    void createsBusinessRolesAndPermissions() throws Exception {
        String admin = adminToken("role-creator");
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "order:read", "name", "Read orders"))
                .andExpect(status().isCreated());
        JsonNode role = json(send(postJson("/admin/api/roles"), admin, Map.of("code", "ORDER_VIEWER",
                "name", "Order viewer", "permissions", List.of("order:read"))).andExpect(status().isCreated()));
        assertThat(role.get("permissions")).extracting(JsonNode::asString).containsExactly("order:read");
        assertThat(role.get("builtIn").asBoolean()).isFalse();
        String userId = createUser("order-viewer", null, "ORDER_VIEWER");
        JsonNode access = JSON.readTree(java.util.Base64.getUrlDecoder().decode(
                userToken("order-viewer").split("\\.")[1]));
        assertThat(access.get("roles")).extracting(JsonNode::asString).contains("ORDER_VIEWER");
        assertThat(access.get("permissions")).extracting(JsonNode::asString).containsExactly("order:read");
        assertThat(json(call(getJson("/admin/api/roles/ORDER_VIEWER"), admin)).get("users").asLong()).isEqualTo(1);
        assertThat(json(call(getJson("/admin/api/permissions/order:read"), admin)).get("roles"))
                .extracting(JsonNode::asString).containsExactly("ORDER_VIEWER");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM admin_audit_log WHERE action IN ('ROLE_CREATED', "
                + "'PERMISSION_CREATED')").query(Integer.class).single()).isGreaterThanOrEqualTo(2);
        assertThat(userId).isNotNull();
    }

    @Test
    @DisplayName("代碼：格式錯誤、as: 開頭、重複；不存在的權限 400／409")
    void validatesCodes() throws Exception {
        String admin = adminToken("code-admin");
        send(postJson("/admin/api/roles"), admin, Map.of("code", "lower", "name", "x")).andExpect(status().isBadRequest());
        send(postJson("/admin/api/roles"), admin, Map.of("code", "GHOST_ROLE", "name", "x",
                "permissions", List.of("no:such"))).andExpect(status().isBadRequest());
        send(postJson("/admin/api/roles"), admin, Map.of("code", "AS_ADMIN", "name", "x")).andExpect(status().isConflict());
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "Order:Read", "name", "x"))
                .andExpect(status().isBadRequest());
        JsonNode reserved = json(send(postJson("/admin/api/permissions"), admin, Map.of("code", "as:user:delete",
                "name", "x")).andExpect(status().isBadRequest()));
        assertThat(reserved.get("errors").get("code").asString()).contains("reserved");
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "report:export", "name", "Export"))
                .andExpect(status().isCreated());
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "report:export", "name", "Export"))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("內建角色與權限：AS_ADMIN 的權限不能變更（名稱可以），內建角色與權限不能刪除（T-ADMIN-07）")
    void protectsBuiltIns() throws Exception {
        String admin = adminToken("builtin-admin");
        send(putJson("/admin/api/roles/AS_ADMIN"), admin, Map.of("name", "Admins", "permissions", List.of("as:user:read")))
                .andExpect(status().isConflict());
        JsonNode renamed = json(send(putJson("/admin/api/roles/AS_ADMIN"), admin, Map.of("name", "Administrators"))
                .andExpect(status().isOk()));
        assertThat(renamed.get("name").asString()).isEqualTo("Administrators");
        assertThat(renamed.get("permissions")).hasSize(8);
        call(deleteJson("/admin/api/roles/AS_SUPPORT"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/permissions/as:audit:read"), admin).andExpect(status().isConflict());
    }

    @Test
    @DisplayName("刪除：仍有使用者的角色、仍被角色使用的權限 409；沒有使用的可以刪除")
    void deletesOnlyUnused() throws Exception {
        String admin = adminToken("delete-admin");
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "invoice:read", "name", "Read invoices"));
        send(postJson("/admin/api/roles"), admin, Map.of("code", "BILLING", "name", "Billing",
                "permissions", List.of("invoice:read")));
        String userId = createUser("billing-user", null, "BILLING");
        call(deleteJson("/admin/api/roles/BILLING"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/permissions/invoice:read"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/users/" + userId + "/roles/BILLING"), admin).andExpect(status().isOk());
        call(deleteJson("/admin/api/roles/BILLING"), admin).andExpect(status().isNoContent());
        call(deleteJson("/admin/api/permissions/invoice:read"), admin).andExpect(status().isNoContent());
        call(getJson("/admin/api/roles/BILLING"), admin).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("更新角色的權限清單；沒有 as:role:read 的使用者不能讀取角色")
    void updatesRolePermissions() throws Exception {
        String admin = adminToken("update-role-admin");
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "stock:read", "name", "Read stock"));
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "stock:write", "name", "Write stock"));
        send(postJson("/admin/api/roles"), admin, Map.of("code", "STOCK", "name", "Stock",
                "permissions", List.of("stock:read")));
        JsonNode updated = json(send(putJson("/admin/api/roles/STOCK"), admin, Map.of("name", "Stock keeper",
                "permissions", List.of("stock:read", "stock:write"))).andExpect(status().isOk()));
        assertThat(updated.get("permissions")).extracting(JsonNode::asString)
                .containsExactly("stock:read", "stock:write");
        createUser("no-role-reader", null, "AS_SUPPORT");
        call(getJson("/admin/api/roles"), userToken("no-role-reader")).andExpect(status().isForbidden());
    }

    // ---- 工作 25：第三方 client、scope、API resource ----

    @Test
    @DisplayName("建立第三方 client：secret 只回傳一次且可用；要求同意；重新產生後舊 secret 失效；稽核不含 secret（T-ADMIN-07）")
    void managesThirdPartyClients() throws Exception {
        String admin = adminToken("client-admin");
        JsonNode created = json(send(postJson("/admin/api/clients"), admin, partnerClient("partner-app"))
                .andExpect(status().isCreated()));
        String secret = created.get("clientSecret").asString();
        JsonNode client = created.get("client");
        assertThat(client.get("trustLevel").asString()).isEqualTo("THIRD_PARTY");
        assertThat(client.get("status").asString()).isEqualTo("ACTIVE");
        assertThat(client.get("configured").asBoolean()).isFalse();
        assertThat(client.get("grantTypes")).extracting(JsonNode::asString)
                .containsExactly("authorization_code", "refresh_token");
        assertThat(client.get("privacyPolicyUrl").asString()).isEqualTo("https://partner.example.com/privacy");
        assertThat(clients.findByClientId("partner-app").getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(tokenEndpointStatus("partner-app", secret)).as("secret 正確：client 驗證通過，授權碼無效").isEqualTo(400);
        assertThat(tokenEndpointStatus("partner-app", "wrong")).isEqualTo(401);

        JsonNode renewed = json(call(postJson("/admin/api/clients/partner-app/secret"), admin)
                .andExpect(status().isOk()));
        assertThat(tokenEndpointStatus("partner-app", secret)).as("舊的 secret 失效").isEqualTo(401);
        assertThat(tokenEndpointStatus("partner-app", renewed.get("clientSecret").asString())).isEqualTo(400);

        JsonNode updated = json(send(patchJson("/admin/api/clients/partner-app"), admin, Map.of("name", "Partner",
                "scopes", List.of("openid", "email"), "logoUrl", "")).andExpect(status().isOk()));
        assertThat(updated.get("name").asString()).isEqualTo("Partner");
        assertThat(updated.get("scopes")).extracting(JsonNode::asString).containsExactly("email", "openid");
        assertThat(updated.get("logoUrl").isNull()).isTrue();
        assertThat(updated.get("privacyPolicyUrl").asString()).as("未指定的欄位不變")
                .isEqualTo("https://partner.example.com/privacy");

        JsonNode audit = json(call(get("/admin/api/audit/admin").param("targetType", "CLIENT")
                .param("targetId", "partner-app"), admin).andExpect(status().isOk()));
        assertThat(audit.get("items")).extracting(entry -> entry.get("action").asString())
                .containsExactly("CLIENT_UPDATED", "CLIENT_SECRET_CHANGED", "CLIENT_CREATED");
        assertThat(audit.toString()).doesNotContain(secret).doesNotContain("bcrypt");
    }

    @Test
    @DisplayName("第三方 client 的規則：必須有隱私權政策、scope 必須存在且不可為 as:；設定檔中的 client 唯讀（409）")
    void refusesInvalidClients() throws Exception {
        String admin = adminToken("strict-client-admin");
        Map<String, Object> noPolicy = new java.util.HashMap<>(partnerClient("no-policy"));
        noPolicy.remove("privacyPolicyUrl");
        noPolicy.put("scopes", List.of("as:user:read"));
        noPolicy.put("redirectUris", List.of("http://partner.example.com/callback"));
        JsonNode problem = json(send(postJson("/admin/api/clients"), admin, noPolicy)
                .andExpect(status().isBadRequest()));
        assertThat(problem.get("errors").get("privacyPolicyUrl").asString()).contains("required");
        assertThat(problem.get("errors").get("scopes").asString()).contains("as:");
        assertThat(problem.get("errors").get("redirectUris").asString()).contains("https");
        Map<String, Object> unknownScope = new java.util.HashMap<>(partnerClient("unknown-scope"));
        unknownScope.put("scopes", List.of("orders.read"));
        assertThat(json(send(postJson("/admin/api/clients"), admin, unknownScope).andExpect(status().isBadRequest()))
                .get("errors").get("scopes").asString()).contains("not defined");

        JsonNode listed = json(call(getJson("/admin/api/clients"), admin).andExpect(status().isOk()));
        assertThat(listed).anySatisfy(client -> {
            assertThat(client.get("clientId").asString()).isEqualTo("web-bff");
            assertThat(client.get("configured").asBoolean()).isTrue();
            assertThat(client.get("trustLevel").asString()).isEqualTo("FIRST_PARTY");
        });
        send(postJson("/admin/api/clients"), admin, partnerClient("web-bff")).andExpect(status().isConflict());
        send(patchJson("/admin/api/clients/web-bff"), admin, Map.of("name", "x")).andExpect(status().isConflict());
        call(postJson("/admin/api/clients/web-bff/secret"), admin).andExpect(status().isConflict());
        call(postJson("/admin/api/clients/web-bff/suspend"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/clients/web-bff"), admin).andExpect(status().isConflict());
        call(getJson("/admin/api/clients/nobody"), admin).andExpect(status().isNotFound());

        createUser("client-reader", null, "AS_SUPPORT");
        call(getJson("/admin/api/clients"), userToken("client-reader")).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Client 狀態：審核中與停權的 client 無法使用；停權刪除授權；核准、重新啟用；刪除後 404")
    void changesClientStatus() throws Exception {
        String admin = adminToken("status-admin");
        Map<String, Object> pending = new java.util.HashMap<>(partnerClient("pending-app"));
        pending.put("status", "PENDING_REVIEW");
        pending.put("authenticationMethod", "none");
        JsonNode created = json(send(postJson("/admin/api/clients"), admin, pending).andExpect(status().isCreated()));
        assertThat(created.get("clientSecret").isNull()).as("public client 沒有 secret").isTrue();
        assertThat(created.get("client").get("grantTypes")).extracting(JsonNode::asString)
                .containsExactly("authorization_code");
        assertThat(clients.findByClientId("pending-app")).as("審核中").isNull();
        call(postJson("/admin/api/clients/pending-app/activate"), admin).andExpect(status().isConflict());
        call(postJson("/admin/api/clients/pending-app/secret"), admin).andExpect(status().isConflict());

        call(postJson("/admin/api/clients/pending-app/approve"), admin).andExpect(status().isOk());
        assertThat(clients.findByClientId("pending-app")).isNotNull();
        String registeredClientId = clients.findByClientId("pending-app").getId();
        jdbc.sql("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type) "
                + "VALUES ('authz-of-pending', :client, 'someone', 'authorization_code')")
                .param("client", registeredClientId).update();

        JsonNode suspended = json(call(postJson("/admin/api/clients/pending-app/suspend"), admin)
                .andExpect(status().isOk()));
        assertThat(suspended.get("status").asString()).isEqualTo("SUSPENDED");
        assertThat(clients.findByClientId("pending-app")).isNull();
        assertThat(jdbc.sql("SELECT COUNT(*) FROM oauth2_authorization WHERE registered_client_id = :client")
                .param("client", registeredClientId).query(Integer.class).single()).as("授權已刪除").isZero();
        call(postJson("/admin/api/clients/pending-app/activate"), admin).andExpect(status().isOk());
        assertThat(clients.findByClientId("pending-app")).isNotNull();

        call(deleteJson("/admin/api/clients/pending-app"), admin).andExpect(status().isNoContent());
        call(getJson("/admin/api/clients/pending-app"), admin).andExpect(status().isNotFound());
        assertThat(jdbc.sql("SELECT COUNT(*) FROM client_profile WHERE registered_client_id = :client")
                .param("client", registeredClientId).query(Integer.class).single()).isZero();
    }

    @Test
    @DisplayName("Scope 與 API resource：建立、更新、權限對應（不可為 as:）；仍在使用或內建時不能刪除")
    void managesScopesAndApiResources() throws Exception {
        String admin = adminToken("scope-admin");
        send(postJson("/admin/api/api-resources"), admin, Map.of("code", "orders-api", "name", "Orders"))
                .andExpect(status().isCreated());
        send(postJson("/admin/api/permissions"), admin, Map.of("code", "shipment:read", "name", "Read shipments"))
                .andExpect(status().isCreated());
        JsonNode problem = json(send(postJson("/admin/api/scopes"), admin, Map.of("code", "orders.admin",
                "displayName", "Admin", "permissions", List.of("as:user:read"))).andExpect(status().isBadRequest()));
        assertThat(problem.get("errors").get("permissions").asString()).contains("as:");
        send(postJson("/admin/api/scopes"), admin, Map.of("code", "as:anything", "displayName", "x"))
                .andExpect(status().isBadRequest());

        JsonNode scope = json(send(postJson("/admin/api/scopes"), admin, Map.of("code", "orders.read",
                "displayName", "Read your orders", "apiResource", "orders-api", "permissions", List.of("shipment:read")))
                .andExpect(status().isCreated()));
        assertThat(scope.get("consentRequired").asBoolean()).isTrue();
        assertThat(scope.get("permissions")).extracting(JsonNode::asString).containsExactly("shipment:read");
        assertThat(json(call(getJson("/admin/api/api-resources/orders-api"), admin).andExpect(status().isOk()))
                .get("scopes")).extracting(JsonNode::asString).containsExactly("orders.read");
        assertThat(json(call(getJson("/admin/api/permissions/shipment:read"), admin)).get("scopes"))
                .extracting(JsonNode::asString).containsExactly("orders.read");

        Map<String, Object> partner = new java.util.HashMap<>(partnerClient("orders-partner"));
        partner.put("scopes", List.of("openid", "orders.read"));
        send(postJson("/admin/api/clients"), admin, partner).andExpect(status().isCreated());
        call(deleteJson("/admin/api/scopes/orders.read"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/api-resources/orders-api"), admin).andExpect(status().isConflict());
        call(deleteJson("/admin/api/scopes/openid"), admin).andExpect(status().isConflict());
        // token.audience 使用中
        call(deleteJson("/admin/api/api-resources/jacky917-api"), admin).andExpect(status().isConflict());

        JsonNode builtIn = json(send(putJson("/admin/api/scopes/profile"), admin, Map.of("displayName", "Profile",
                "consentRequired", false, "permissions", List.of("shipment:read"))).andExpect(status().isOk()));
        assertThat(builtIn.get("displayName").asString()).isEqualTo("Profile");
        assertThat(builtIn.get("consentRequired").asBoolean()).as("內建 scope 只改名稱與說明").isTrue();
        assertThat(builtIn.get("permissions")).isEmpty();

        call(deleteJson("/admin/api/clients/orders-partner"), admin).andExpect(status().isNoContent());
        call(deleteJson("/admin/api/scopes/orders.read"), admin).andExpect(status().isNoContent());
        call(deleteJson("/admin/api/api-resources/orders-api"), admin).andExpect(status().isNoContent());
        JsonNode audit = json(call(get("/admin/api/audit/admin").param("targetType", "SCOPE")
                .param("targetId", "orders.read"), admin));
        assertThat(audit.get("items")).extracting(entry -> entry.get("action").asString())
                .containsExactly("SCOPE_DELETED", "SCOPE_CREATED");
    }

    // ---- 審查後的補強 ----

    @Test
    @DisplayName("管理稽核記錄操作者：使用者 token 記錄使用者與 client；client_credentials 只記錄 client；可依操作者篩選")
    void recordsTheOperator() throws Exception {
        String adminId = createUser("operator-admin", null, "AS_ADMIN");
        String admin = userToken("operator-admin");
        String userId = json(send(postJson("/admin/api/users"), admin, Map.of("username", "operated-user",
                "password", PASSWORD)).andExpect(status().isCreated())).get("user").get("id").asString();
        Map<String, Object> row = jdbc.sql("SELECT operator_user_id, operator_client, ip_address FROM admin_audit_log "
                + "WHERE action = 'USER_CREATED' AND target_id = :id").param("id", userId).query().singleRow();
        assertThat(row).containsEntry("operator_user_id", adminId).containsEntry("operator_client", "web-bff");
        assertThat(row.get("ip_address")).isNotNull();
        JsonNode filtered = json(call(get("/admin/api/audit/admin").param("operatorUserId", adminId), admin)
                .andExpect(status().isOk()));
        assertThat(filtered.get("items")).extracting(entry -> entry.get("targetId").asString()).contains(userId);

        String machine = json(mockMvc.perform(post("/oauth2/token").with(httpBasic("admin-sync", "sync-secret"))
                .param("grant_type", "client_credentials").param("scope", "as:audit:read as:user:read"))
                .andExpect(status().isOk())).get("access_token").asString();
        call(get("/admin/api/users/" + userId), machine).andExpect(status().isOk());
        // admin-sync 沒有 as:user:write
        call(postJson("/admin/api/users/" + userId + "/unlock"), machine).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("錯誤回應：型別錯誤與缺少參數指出欄位；不是 JSON 的本文說明原因；顯示名稱過長為 400 而不是 500")
    void explainsBadRequests() throws Exception {
        String admin = adminToken("explaining-admin");
        JsonNode mismatch = json(call(get("/admin/api/users").param("page", "abc"), admin)
                .andExpect(status().isBadRequest()));
        assertThat(mismatch.get("errors").get("page").asString()).isEqualTo("must be a valid int");
        JsonNode body = json(call(postJson("/admin/api/users").contentType(MediaType.APPLICATION_JSON)
                .content("{not json"), admin).andExpect(status().isBadRequest()));
        assertThat(body.get("detail").asString()).contains("not valid JSON");
        JsonNode tooLong = json(send(postJson("/admin/api/users"), admin, Map.of("username", "long-name-user",
                "displayName", "名".repeat(129))).andExpect(status().isBadRequest()));
        assertThat(tooLong.get("errors").get("displayName").asString()).contains("at most 128");
    }

    @Test
    @DisplayName("權限矩陣：AS_SUPPORT 可撤銷 Session 但不能修改使用者、不能管理 client、不能重設兩步驟驗證")
    void supportHasOnlyItsPermissions() throws Exception {
        String userId = createUser("matrix-user", null);
        createUser("matrix-support", null, "AS_SUPPORT");
        String support = userToken("matrix-support");
        call(deleteJson("/admin/api/users/" + userId + "/sessions"), support).andExpect(status().is2xxSuccessful());
        send(patchJson("/admin/api/users/" + userId), support, Map.of("displayName", "x"))
                .andExpect(status().isForbidden());
        call(getJson("/admin/api/clients"), support).andExpect(status().isForbidden());
        send(postJson("/admin/api/clients"), support, partnerClient("matrix-client")).andExpect(status().isForbidden());
        call(deleteJson("/admin/api/users/" + userId + "/mfa"), support).andExpect(status().isForbidden());
        send(putJson("/admin/api/roles/USER"), support, Map.of("name", "x")).andExpect(status().isForbidden());
    }

    // ---- 共用工具 ----

    /**
     * 建立擁有 {@code AS_ADMIN} 的使用者並取得其 token。
     */
    String adminToken(String username) throws Exception {
        createUser(username, null, "AS_ADMIN");
        return userToken(username);
    }

    /**
     * 以密碼登入取得使用者的 Access Token（第一方 client，含使用者的全部權限）。
     */
    String userToken(String username) throws Exception {
        if (jdbc.sql("SELECT COUNT(*) FROM app_user WHERE username = :u").param("u", username).query(Integer.class)
                .single() == 0) {
            createUser(username, null);
        }
        return logInAndExchangeCode(username).tokens().get("access_token").asString();
    }

    /**
     * 以 starter 的金鑰簽一個自訂 claim 的 token（issuer 為本 AS）。
     */
    String mint(Map<String, Object> claims) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("http://localhost:9000").subject("someone")
                .issuedAt(now).expiresAt(now.plusSeconds(300));
        claims.forEach(builder::claim);
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),
                builder.build())).getTokenValue();
    }

    ResultActions call(MockHttpServletRequestBuilder request, String token) throws Exception {
        return mockMvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
    }

    ResultActions send(MockHttpServletRequestBuilder request, String token, Object body) throws Exception {
        return call(request.contentType(MediaType.APPLICATION_JSON).content(JSON.writeValueAsString(body)), token);
    }

    JsonNode json(ResultActions result) throws Exception {
        String body = result.andReturn().getResponse().getContentAsString();
        return body.isEmpty() ? JSON.nullNode() : JSON.readTree(body);
    }

    static Map<String, Object> partnerClient(String clientId) {
        return Map.of("clientId", clientId, "name", "Partner App", "description", "Imports your orders",
                "redirectUris", List.of("https://partner.example.com/callback"), "scopes", List.of("openid", "profile"),
                "privacyPolicyUrl", "https://partner.example.com/privacy",
                "logoUrl", "https://partner.example.com/logo.png");
    }

    /**
     * 以 client 的 secret 呼叫 token 端點（授權碼無效）：client 驗證通過時 400，失敗時 401。
     */
    int tokenEndpointStatus(String clientId, String secret) throws Exception {
        return mockMvc.perform(post("/oauth2/token").with(httpBasic(clientId, secret))
                        .param("grant_type", "authorization_code").param("code", "not-a-code")
                        .param("redirect_uri", "https://partner.example.com/callback"))
                .andReturn().getResponse().getStatus();
    }

    static MockHttpServletRequestBuilder getJson(String path) {
        return get(path);
    }

    static MockHttpServletRequestBuilder postJson(String path) {
        return post(path);
    }

    static MockHttpServletRequestBuilder putJson(String path) {
        return put(path);
    }

    static MockHttpServletRequestBuilder patchJson(String path) {
        return patch(path);
    }

    static MockHttpServletRequestBuilder deleteJson(String path) {
        return delete(path);
    }
}
