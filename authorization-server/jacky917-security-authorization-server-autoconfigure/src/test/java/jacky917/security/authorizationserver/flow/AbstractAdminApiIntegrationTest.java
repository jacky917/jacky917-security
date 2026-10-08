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

    // ---- 共用工具 ----

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
