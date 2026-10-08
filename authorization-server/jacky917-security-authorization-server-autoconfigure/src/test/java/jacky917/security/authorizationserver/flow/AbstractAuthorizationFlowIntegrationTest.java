package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.refresh.RefreshTokenHistoryRepository;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.token.TokenClaimsContributor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;

import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
/**
 * 以 MockMvc 模擬瀏覽器與 BFF 走完授權碼流程：授權請求 → 登入頁（從 HTML 取得 CSRF token）→ 登入
 * → 授權碼 → 以 PKCE 換 Token。子類別分別以 SQLite 與 PostgreSQL 執行（詳細設計 T-LOGIN-01、
 * T-CLIENT-01、T-CLIENT-02、T-TOKEN-03 的基本部分）。
 */
abstract class AbstractAuthorizationFlowIntegrationTest extends AbstractFlowIntegrationTest {

    @Test
    @DisplayName("授權碼 + PKCE 完整流程：登入後建立 auth_session，換到的 Access Token 的 sub 為使用者 ID")
    void authorizationCodeFlow() throws Exception {
        LoggedIn result = logInAndExchangeCode("admin");
        Map<String, Object> authSession = jdbc.sql("SELECT login_method, idp, amr, status FROM auth_session "
                + "WHERE session_id = :id").param("id", result.asid()).query().singleRow();
        assertThat(authSession).containsEntry("login_method", "PASSWORD").containsEntry("idp", "local")
                .containsEntry("amr", "pwd").containsEntry("status", "ACTIVE");

        assertThat(result.tokens().has("refresh_token")).isTrue();
        assertThat(result.tokens().has("id_token")).isTrue();
        Jwt accessToken = jwtDecoder.decode(result.tokens().get("access_token").asString());
        assertThat(accessToken.getSubject()).isEqualTo(result.userId());
        assertThat(accessToken.getIssuer().toString()).isEqualTo("http://localhost:9000");
        assertThat(accessToken.getHeaders()).containsKey("kid");

        // 詳細設計 §5.2：授權在發出授權碼時與登入 Session 連結；換 Token 不會重複建立
        assertThat(jdbc.sql("SELECT a.principal_name FROM session_authorization sa JOIN oauth2_authorization a "
                        + "ON a.id = sa.authorization_id WHERE sa.session_id = :asid")
                .param("asid", result.asid()).query(String.class).list()).containsExactly(result.userId());
    }

    @Test
    @DisplayName("刷新：換發新的 Refresh Token（輪換），授權與登入 Session 的連結維持不變")
    void refreshKeepsTheSessionLink() throws Exception {
        LoggedIn result = logInAndExchangeCode("admin");
        String firstRefreshToken = result.tokens().get("refresh_token").asString();
        JsonNode refreshed = tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                .param("grant_type", "refresh_token").param("refresh_token", firstRefreshToken)));
        assertThat(refreshed.get("refresh_token").asString()).isNotEqualTo(firstRefreshToken);
        assertThat(jwtDecoder.decode(refreshed.get("access_token").asString()).getSubject()).isEqualTo(result.userId());

        // 舊的 Refresh Token 已失效
        mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                        .param("grant_type", "refresh_token").param("refresh_token", firstRefreshToken))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.sql("SELECT session_id FROM session_authorization sa JOIN oauth2_authorization a "
                        + "ON a.id = sa.authorization_id WHERE a.principal_name = :user AND sa.session_id = :asid")
                .param("user", result.userId()).param("asid", result.asid()).query(String.class).list()).hasSize(1);
    }

    @Test
    @DisplayName("沒有 asid 或 asid 不屬於同一位使用者的新授權被拒絕，且不會留下授權資料")
    void authorizationWithoutLoginSessionIsRejected() throws Exception {
        LoggedIn other = logInAndExchangeCode("admin");
        RegisteredClient client = clients.findByClientId("web-bff");
        for (String asid : new String[]{null, other.asid()}) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            if (asid != null) {
                request.getSession(true).setAttribute(AuthSessionService.SESSION_ATTRIBUTE, asid);
            }
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
            try {
                String id = java.util.UUID.randomUUID().toString();
                OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client).id(id)
                        .principalName("someone-else").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .build();
                assertThatThrownBy(() -> authorizations.save(authorization)).isInstanceOf(IllegalStateException.class);
                assertThat(authorizations.findById(id)).as("交易回滾，不留下沒有連結的授權").isNull();
            } finally {
                RequestContextHolder.resetRequestAttributes();
            }
        }
    }

    @Test
    @DisplayName("第一方 Access Token 的 claim（T-TOKEN-01）；ID Token 有 sid、amr、name，沒有角色與權限（T-TOKEN-04）")
    void tokenClaims() throws Exception {
        String userId = createUser("token-user", "Token User", "AS_SUPPORT");
        LoggedIn result = logInAndExchangeCode("token-user");

        Jwt access = jwtDecoder.decode(result.tokens().get("access_token").asString());
        assertThat(access.getAudience()).containsExactly("jacky917-api");
        assertThat(access.getClaimAsString("client_id")).isEqualTo("web-bff");
        assertThat(access.getClaimAsString("asid")).isEqualTo(result.asid());
        assertThat(access.getClaimAsString("idp")).isEqualTo("local");
        assertThat(access.getClaimAsStringList("roles")).containsExactlyInAnyOrder("USER", "AS_SUPPORT");
        assertThat(access.getClaimAsStringList("permissions"))
                .containsExactlyInAnyOrder("as:user:read", "as:session:revoke", "as:audit:read");
        assertThat(access.getClaimAsStringList("scope")).containsExactlyInAnyOrder("openid", "profile");
        assertThat(access.getClaims()).doesNotContainKeys("email", "name");

        Jwt id = jwtDecoder.decode(result.tokens().get("id_token").asString());
        assertThat(id.getSubject()).isEqualTo(userId);
        assertThat(id.getAudience()).containsExactly("web-bff");
        assertThat(id.getClaims()).containsKeys("sid", "auth_time").doesNotContainKeys("roles", "permissions", "asid");
        assertThat(id.getClaimAsStringList("amr")).containsExactly("pwd");
        assertThat(id.getClaimAsString("name")).isEqualTo("Token User");
        assertThat(id.getClaims()).as("沒有要求 email scope").doesNotContainKey("email");
    }

    @Test
    @DisplayName("移除角色後刷新：新的 Access Token 已沒有該角色（D18、T-TOKEN-05）")
    void refreshReflectsRoleChanges() throws Exception {
        String userId = createUser("role-user", null, "AS_SUPPORT");
        LoggedIn result = logInAndExchangeCode("role-user");
        jdbc.sql("DELETE FROM app_user_role WHERE user_id = :user AND role_id = (SELECT id FROM app_role WHERE code = 'AS_SUPPORT')")
                .param("user", userId).update();
        Jwt refreshed = jwtDecoder.decode(refresh(result).get("access_token").asString());
        assertThat(refreshed.getClaimAsStringList("roles")).containsExactly("USER");
        assertThat(refreshed.getClaimAsStringList("permissions")).isEmpty();
        assertThat(refreshed.getClaimAsStringList("tenants")).as("TokenClaimsContributor 的 claim")
                .containsExactly("tenant-a", "tenant-b");
    }

    @Test
    @DisplayName("登入 Session 被撤銷後刷新：invalid_grant")
    void refreshIsRefusedWhenSessionIsRevoked() throws Exception {
        createUser("revoked-user", null);
        LoggedIn revoked = logInAndExchangeCode("revoked-user");
        jdbc.sql("UPDATE auth_session SET status = 'REVOKED', revoked_at = :now, revoke_reason = 'ADMIN' WHERE session_id = :id")
                .param("now", java.sql.Timestamp.from(java.time.Instant.now())).param("id", revoked.asid()).update();
        assertRefreshRefused(revoked);
    }

    @Test
    @DisplayName("使用者停用後刷新：invalid_grant，並撤銷登入 Session（T-REFRESH-04）")
    void refreshIsRefusedAndSessionRevokedWhenUserIsDisabled() throws Exception {
        String disabledId = createUser("disabled-user", null);
        LoggedIn disabled = logInAndExchangeCode("disabled-user");
        jdbc.sql("UPDATE app_user SET status = 'DISABLED' WHERE id = :id").param("id", disabledId).update();
        assertRefreshRefused(disabled);
        assertSession(disabled.asid(), "REVOKED", "USER_DISABLED");
        assertThat(authorizationCount(disabled.asid())).as("授權一併刪除").isZero();
    }

    @Test
    @DisplayName("變更密碼後，之前登入的 Session 刷新：invalid_grant，並撤銷（T-REFRESH-05）")
    void refreshIsRefusedAfterPasswordChange() throws Exception {
        String userId = createUser("password-user", null);
        LoggedIn before = logInAndExchangeCode("password-user");
        clock.advance(Duration.ofMinutes(1));
        jdbc.sql("UPDATE app_user SET password_changed_at = :at WHERE id = :id")
                .param("at", java.sql.Timestamp.from(clock.instant())).param("id", userId).update();
        assertRefreshRefused(before);
        assertSession(before.asid(), "REVOKED", "PASSWORD_CHANGED");

        clock.advance(Duration.ofMinutes(1));
        LoggedIn after = logInAndExchangeCode("password-user");
        assertThat(refresh(after).has("access_token")).as("變更密碼之後的登入可以刷新").isTrue();
    }

    @Test
    @DisplayName("暫時鎖定（連續登入失敗）只阻擋密碼登入，已登入的 Session 仍可刷新")
    void temporaryLockDoesNotBlockRefresh() throws Exception {
        String lockedId = createUser("locked-user", null);
        LoggedIn locked = logInAndExchangeCode("locked-user");
        jdbc.sql("UPDATE app_user SET locked_until = :until WHERE id = :id")
                .param("until", java.sql.Timestamp.from(clock.instant().plusSeconds(600))).param("id", lockedId).update();
        assertThat(refresh(locked).has("access_token")).isTrue();
        assertSession(locked.asid(), "ACTIVE", null);
    }

    @Test
    @DisplayName("刷新後舊的 Refresh Token 以雜湊記錄在 refresh_token_history（T-REFRESH-01）")
    void rotatedRefreshTokenIsRemembered() throws Exception {
        createUser("history-user", null);
        LoggedIn result = logInAndExchangeCode("history-user");
        String old = result.tokens().get("refresh_token").asString();
        clock.advance(Duration.ofMinutes(5));
        refresh(result);
        Map<String, Object> row = jdbc.sql("SELECT session_id, user_id, rotated_at, expires_at FROM refresh_token_history "
                        + "WHERE token_hash = :hash")
                .param("hash", RefreshTokenHistoryRepository.hash(old)).query().singleRow();
        assertThat(row).containsEntry("session_id", result.asid()).containsEntry("user_id", result.userId());
        assertThat(jdbc.sql("SELECT COUNT(*) FROM refresh_token_history WHERE token_hash = :token")
                .param("token", old).query(Integer.class).single()).as("不儲存 token 本身").isZero();
        Map<String, Object> session = jdbc.sql("SELECT created_at, last_seen_at FROM auth_session WHERE session_id = :id")
                .param("id", result.asid()).query((rs, n) -> Map.<String, Object>of(
                        "created", rs.getTimestamp("created_at").toInstant(), "seen", rs.getTimestamp("last_seen_at").toInstant()))
                .single();
        assertThat(Duration.between((java.time.Instant) session.get("created"), (java.time.Instant) session.get("seen")))
                .as("刷新時更新 last_seen_at").isGreaterThanOrEqualTo(Duration.ofMinutes(5));
    }

    @Test
    @DisplayName("寬限期內重用舊的 Refresh Token：invalid_grant，但 Session 不撤銷，新的 Refresh Token 仍可用（D19）")
    void reuseWithinGracePeriodKeepsTheSession() throws Exception {
        createUser("grace-user", null);
        LoggedIn result = logInAndExchangeCode("grace-user");
        String old = result.tokens().get("refresh_token").asString();
        JsonNode refreshed = refresh(result);
        // 寬限期 30 秒。MutableClock 跟著系統時間走，刷新到重用之間的執行時間也會計入，因此推移 29 秒，
        // 保留約 1 秒給執行時間（超過 1 秒會讓測試不穩定）
        clock.advance(Duration.ofSeconds(29));
        assertRefreshRefused(old);
        assertSession(result.asid(), "ACTIVE", null);
        assertThat(refresh(refreshed.get("refresh_token").asString()).has("access_token")).isTrue();
    }

    @Test
    @DisplayName("超過寬限期重用舊的 Refresh Token：invalid_grant、撤銷 Session、新的 Refresh Token 也失效、寫入稽核（T-REFRESH-03）")
    void reuseAfterGracePeriodRevokesTheSession() throws Exception {
        createUser("reuse-user", null);
        LoggedIn result = logInAndExchangeCode("reuse-user");
        String old = result.tokens().get("refresh_token").asString();
        JsonNode refreshed = refresh(result);
        clock.advance(Duration.ofSeconds(31));
        assertRefreshRefused(old);
        assertSession(result.asid(), "REVOKED", "REUSE_DETECTED");
        assertRefreshRefused(refreshed.get("refresh_token").asString());
        Map<String, Object> audit = jdbc.sql("SELECT user_id, session_id, success, failure_reason FROM login_audit "
                        + "WHERE event_type = 'TOKEN_REFRESH_REUSE' AND session_id = :asid")
                .param("asid", result.asid()).query().singleRow();
        assertThat(audit).containsEntry("user_id", result.userId()).containsEntry("failure_reason", "REUSE_DETECTED");
        assertThat(audit.get("success")).isIn(false, 0);
    }

    @Test
    @DisplayName("同一個 Refresh Token 的兩個併發刷新：一個成功、一個 invalid_grant，Session 不撤銷，成功拿到的新 "
            + "token 可以再刷新（T-REFRESH-02）")
    void concurrentRefreshesAreSerialized() throws Exception {
        createUser("concurrent-user", null);
        LoggedIn result = logInAndExchangeCode("concurrent-user");
        String token = result.tokens().get("refresh_token").asString();
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        // 第一個刷新持有列鎖時多等一下：沒有列鎖或重讀時，第二個刷新必定會在此期間完成並拿到第二組 token
        holdRefreshLockFor = Duration.ofMillis(300);
        java.util.List<org.springframework.mock.web.MockHttpServletResponse> responses;
        try {
            java.util.concurrent.Callable<org.springframework.mock.web.MockHttpServletResponse> request = () -> {
                start.await();
                return mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                                .param("grant_type", "refresh_token").param("refresh_token", token))
                        .andReturn().getResponse();
            };
            java.util.concurrent.Future<org.springframework.mock.web.MockHttpServletResponse> first =
                    executor.submit(request);
            java.util.concurrent.Future<org.springframework.mock.web.MockHttpServletResponse> second =
                    executor.submit(request);
            start.countDown();
            responses = java.util.List.of(first.get(), second.get());
        } finally {
            holdRefreshLockFor = Duration.ZERO;
            executor.shutdownNow();
        }
        assertThat(responses).extracting(org.springframework.mock.web.MockHttpServletResponse::getStatus)
                .containsExactlyInAnyOrder(200, 400);
        org.springframework.mock.web.MockHttpServletResponse refused = responses.stream()
                .filter(response -> response.getStatus() == 400).findFirst().orElseThrow();
        assertThat(refused.getContentAsString()).contains("invalid_grant");
        org.springframework.mock.web.MockHttpServletResponse issued = responses.stream()
                .filter(response -> response.getStatus() == 200).findFirst().orElseThrow();
        String newToken = JSON.readTree(issued.getContentAsString()).get("refresh_token").asString();
        assertSession(result.asid(), "ACTIVE", null);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM refresh_token_history WHERE session_id = :asid")
                .param("asid", result.asid()).query(Integer.class).single()).as("只輪換了一次").isEqualTo(1);
        assertThat(refresh(newToken).has("access_token")).as("成功的那一次拿到的新 token 可以再刷新").isTrue();
    }

    @Test
    @DisplayName("第三方 client：沒有角色，權限只有「使用者擁有」且「scope 涵蓋」的部分（D07、T-TOKEN-02）")
    void thirdPartyClientsGetScopedPermissionsOnly() throws Exception {
        createUser("third-user", null, "AS_ADMIN");
        LoggedIn result = logInAndExchangeCode("third-user");
        String clientId = clients.findByClientId("web-bff").getId();
        try {
            jdbc.sql("UPDATE client_profile SET trust_level = 'THIRD_PARTY', privacy_policy_url = 'https://app.example.com/privacy' "
                    + "WHERE registered_client_id = :id").param("id", clientId).update();
            jdbc.sql("INSERT INTO app_scope_permission (scope_code, permission_id) "
                    + "SELECT 'profile', id FROM app_permission WHERE code IN ('as:user:read', 'as:audit:read')").update();
            Jwt refreshed = jwtDecoder.decode(refresh(result).get("access_token").asString());
            assertThat(refreshed.getClaims()).doesNotContainKey("roles");
            assertThat(refreshed.getClaimAsStringList("permissions")).containsExactlyInAnyOrder("as:user:read", "as:audit:read");
        } finally {
            jdbc.sql("DELETE FROM app_scope_permission WHERE scope_code = 'profile'").update();
            jdbc.sql("UPDATE client_profile SET trust_level = 'FIRST_PARTY' WHERE registered_client_id = :id")
                    .param("id", clientId).update();
        }
    }

    @Test
    @DisplayName("登入 Session 超過絕對有效期（90 天）後刷新：invalid_grant（T-REFRESH-06）")
    void refreshIsRefusedAfterSessionMaxAge() throws Exception {
        createUser("old-session-user", null);
        LoggedIn result = logInAndExchangeCode("old-session-user");
        clock.advance(Duration.ofDays(89));
        JsonNode refreshed = refresh(result);
        assertThat(jwtDecoder.decode(refreshed.get("access_token").asString()).getSubject())
                .as("89 天時仍可刷新").isEqualTo(result.userId());
        clock.advance(Duration.ofDays(2));
        // 刷新會輪換 Refresh Token，因此以最新的那一個測試
        assertRefreshRefused(refreshed.get("refresh_token").asString());
    }

    @Test
    @DisplayName("瀏覽器仍登入、但登入 Session 已被撤銷：授權請求回到登入頁（不是錯誤頁），重新登入後繼續")
    void revokedLoginSessionSendsTheBrowserBackToLogin() throws Exception {
        createUser("revoked-browser-user", null);
        MockHttpSession browser = new MockHttpSession();
        LoggedIn first = logInAndExchangeCode("revoked-browser-user", browser);
        jdbc.sql("UPDATE auth_session SET status = 'REVOKED', revoked_at = :now, revoke_reason = 'ADMIN' WHERE session_id = :id")
                .param("now", java.sql.Timestamp.from(java.time.Instant.now())).param("id", first.asid()).update();

        LoggedIn second = logInAndExchangeCode("revoked-browser-user", browser);
        assertThat(second.asid()).as("重新登入建立新的登入 Session").isNotEqualTo(first.asid());
        assertThat(jwtDecoder.decode(second.tokens().get("access_token").asString()).getClaimAsString("asid"))
                .isEqualTo(second.asid());
    }

    @Test
    @DisplayName("瀏覽器仍登入、但登入 Session 已過期：授權請求回到登入頁")
    void expiredLoginSessionSendsTheBrowserBackToLogin() throws Exception {
        createUser("expired-browser-user", null);
        MockHttpSession browser = new MockHttpSession();
        logInAndExchangeCode("expired-browser-user", browser);
        clock.advance(Duration.ofDays(91));
        mockMvc.perform(get(authorizeUrl(challenge(randomVerifier()))).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
    }

    @Test
    @DisplayName("/userinfo：以 Access Token 取得使用者資料（sub、name）；沒有 token 時 401")
    void userInfo() throws Exception {
        createUser("userinfo-user", "User Info");
        LoggedIn result = logInAndExchangeCode("userinfo-user");
        JsonNode userInfo = JSON.readTree(mockMvc.perform(get("/userinfo")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + result.tokens().get("access_token").asString()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(userInfo.get("sub").asString()).isEqualTo(result.userId());
        assertThat(userInfo.get("name").asString()).isEqualTo("User Info");
        // 不帶 token 的 API 呼叫回 401（瀏覽器的 Accept: text/html 則會導向登入頁）
        mockMvc.perform(get("/userinfo").accept(MediaType.APPLICATION_JSON)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("密碼錯誤 → /login?error；頁面依語言顯示相同的錯誤訊息")
    void wrongPassword() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String csrf = csrfToken(session);
        mockMvc.perform(post("/login").session(session)
                        .param("username", "admin").param("password", "wrong password!").param("_csrf", csrf))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));
        String page = mockMvc.perform(get("/login?error").header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("帳號或密碼錯誤").contains("lang=\"zh-TW\"");
        String english = mockMvc.perform(get("/login?error").header(HttpHeaders.ACCEPT_LANGUAGE, "en"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(english).contains("Incorrect username or password.");
    }

    @Test
    @DisplayName("登入頁不可被嵌入 iframe，並帶內容安全政策")
    void loginPageHeaders() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy",
                        org.hamcrest.Matchers.containsString("frame-ancestors 'none'")));
    }

    @Test
    @DisplayName("沒有 PKCE 的授權請求被拒絕（T-CLIENT-02）")
    void authorizationRequestWithoutPkceIsRejected() throws Exception {
        String url = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", REDIRECT_URI).queryParam("scope", "openid").queryParam("state", "s")
                .build().toUriString();
        MvcResult result = mockMvc.perform(get(url).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).startsWith(REDIRECT_URI).contains("error=invalid_request");
    }

    @Test
    @DisplayName("未註冊的 redirect_uri：直接回 400，不重導")
    void unregisteredRedirectUriIsNotFollowed() throws Exception {
        String url = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", "https://evil.example.com/callback").queryParam("scope", "openid")
                .queryParam("code_challenge", challenge(randomVerifier())).queryParam("code_challenge_method", "S256")
                .build().toUriString();
        mockMvc.perform(get(url).accept(MediaType.TEXT_HTML)).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("client_credentials：Access Token 的 sub 為 client_id（T-TOKEN-03 的基本部分）")
    void clientCredentials() throws Exception {
        JsonNode tokens = tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("report-batch", "batch-secret"))
                .param("grant_type", "client_credentials").param("scope", "report.generate")));
        assertThat(tokens.has("refresh_token")).isFalse();
        Jwt accessToken = jwtDecoder.decode(tokens.get("access_token").asString());
        assertThat(accessToken.getSubject()).isEqualTo("report-batch");
        assertThat(accessToken.getClaimAsStringList("scope")).containsExactly("report.generate");
        assertThat(accessToken.getAudience()).containsExactly("jacky917-api");
        assertThat(accessToken.getClaimAsString("client_id")).isEqualTo("report-batch");
        assertThat(accessToken.getClaims()).doesNotContainKeys("asid", "idp", "roles", "permissions");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM session_authorization WHERE registered_client_id = "
                + "(SELECT id FROM oauth2_registered_client WHERE client_id = 'report-batch')")
                .query(Integer.class).single()).as("client_credentials 沒有登入 Session").isZero();
    }

    @Test
    @DisplayName("停權的 client 換 Token：401 invalid_client（T-CLIENT-01）")
    void suspendedClientIsRejected() throws Exception {
        jdbc.sql("UPDATE client_profile SET status = 'SUSPENDED' WHERE registered_client_id = "
                + "(SELECT id FROM oauth2_registered_client WHERE client_id = 'suspended')").update();
        String body = mockMvc.perform(post("/oauth2/token").with(httpBasic("suspended", "suspended-secret"))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("invalid_client");
    }

    @Test
    @DisplayName("OIDC discovery 的 issuer 與設定相同；JWKS 只有公鑰")
    void discoveryAndJwks() throws Exception {
        JsonNode discovery = JSON.readTree(mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(discovery.get("issuer").asString()).isEqualTo("http://localhost:9000");
        JsonNode jwks = JSON.readTree(mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(jwks.get("keys")).hasSize(1);
        assertThat(jwks.get("keys").get(0).has("d")).isFalse();
    }
}
