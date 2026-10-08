package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.admin.AdminAuditService;
import jacky917.security.authorizationserver.admin.AdminAuditTarget;
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
    @DisplayName("管理稽核：記錄操作者、對象與快照；可依對象篩選")
    void recordsAdminActions() throws Exception {
        String adminId = createUser("audit-admin", null, "AS_ADMIN");
        String token = userToken("audit-admin");
        adminAudit.record("TEST_ACTION", AdminAuditTarget.API_RESOURCE, "order-api", null, Map.of("name", "Orders"));
        JsonNode page = json(call(get("/admin/api/audit/admin").param("targetType", "API_RESOURCE")
                .param("targetId", "order-api"), token).andExpect(status().isOk()));
        assertThat(page.get("items")).hasSize(1);
        JsonNode entry = page.get("items").get(0);
        assertThat(entry.get("action").asString()).isEqualTo("TEST_ACTION");
        assertThat(JSON.readTree(entry.get("after").asString()).get("name").asString()).isEqualTo("Orders");
        assertThat(adminId).isNotNull();
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
    @DisplayName("migration V1_1_0：新的稽核事件種類與管理稽核對象可以寫入")
    void newAuditValuesAreAllowed() {
        for (String type : List.of("USER_REGISTERED", "EMAIL_VERIFIED", "PASSWORD_RESET", "MFA_ENABLED",
                "MFA_DISABLED", "CONSENT_GRANTED", "CONSENT_REVOKED")) {
            jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, success) VALUES (:at, :type, :ok)")
                    .param("at", Timestamp.from(Instant.now())).param("type", type).param("ok", true).update();
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
