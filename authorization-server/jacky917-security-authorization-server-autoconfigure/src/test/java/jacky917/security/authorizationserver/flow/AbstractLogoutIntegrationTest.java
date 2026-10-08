package jacky917.security.authorizationserver.flow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 登出與帳號頁（詳細設計 §5.5、§5.6，T-LOGOUT-01～04）：登出會撤銷整個登入 Session，Refresh Token 立即失效。
 */
abstract class AbstractLogoutIntegrationTest extends AbstractFlowIntegrationTest {

    @Test
    @DisplayName("RP-Initiated Logout：撤銷 Session、刪除授權、Refresh Token 失效、寫入稽核、導回 client（T-LOGOUT-01）")
    void rpInitiatedLogoutRevokesTheSession() throws Exception {
        createUser("logout-user", null);
        LoggedIn result = logInAndExchangeCode("logout-user");
        mockMvc.perform(get(logoutUrl(result.tokens().get("id_token").asString(), LOGGED_OUT_URI, "bye")).session(result.browser()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, LOGGED_OUT_URI + "?state=bye"));

        assertSession(result.asid(), "REVOKED", "LOGOUT");
        assertThat(authorizationCount(result.asid())).isZero();
        assertRefreshRefused(result);
        Map<String, Object> audit = jdbc.sql("SELECT user_id, registered_client_id FROM login_audit "
                + "WHERE event_type = 'LOGOUT' AND session_id = :asid").param("asid", result.asid()).query().singleRow();
        assertThat(audit).containsEntry("user_id", result.userId())
                .containsEntry("registered_client_id", clients.findByClientId("web-bff").getId());
        // 瀏覽器的登入也一併結束
        mockMvc.perform(get(authorizeUrl(challenge(randomVerifier()))).session(result.browser()).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
    }

    @Test
    @DisplayName("瀏覽器 Session 已不存在時登出：以 id_token_hint 找到並撤銷 Session（T-LOGOUT-02）")
    void logoutWithoutBrowserSession() throws Exception {
        createUser("expired-browser-logout", null);
        LoggedIn result = logInAndExchangeCode("expired-browser-logout");
        mockMvc.perform(get(logoutUrl(result.tokens().get("id_token").asString(), LOGGED_OUT_URI, null)).session(new MockHttpSession()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, LOGGED_OUT_URI));
        assertSession(result.asid(), "REVOKED", "LOGOUT");
        assertRefreshRefused(result);
    }

    @Test
    @DisplayName("未註冊的 post_logout_redirect_uri：不重導，Session 不撤銷（T-LOGOUT-03）")
    void unregisteredPostLogoutRedirectIsRejected() throws Exception {
        createUser("bad-redirect-logout", null);
        LoggedIn result = logInAndExchangeCode("bad-redirect-logout");
        MvcResult response = mockMvc.perform(get(logoutUrl(result.tokens().get("id_token").asString(), "https://evil.example.com/", null)).session(result.browser()))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(response.getResponse().getHeader(HttpHeaders.LOCATION)).isNull();
        assertThat(response.getResponse().getErrorMessage()).as("拒絕的原因是 redirect URI，而不是其他參數")
                .contains("post_logout_redirect_uri");
        assertSession(result.asid(), "ACTIVE", null);
    }

    @Test
    @DisplayName("以已過期的 ID Token 登出：只要授權仍存在就撤銷 Session（T-LOGOUT-04）")
    void logoutWithExpiredIdToken() throws Exception {
        createUser("expired-id-token", null);
        LoggedIn result = logInAndExchangeCode("expired-id-token");
        // 模擬 2 小時前簽發、1 小時前到期的 ID Token
        jdbc.sql("UPDATE oauth2_authorization SET oidc_id_token_issued_at = :issued, oidc_id_token_expires_at = :expired "
                        + "WHERE principal_name = :user")
                .param("issued", Timestamp.from(Instant.now().minusSeconds(7200)))
                .param("expired", Timestamp.from(Instant.now().minusSeconds(3600)))
                .param("user", result.userId()).update();
        mockMvc.perform(get(logoutUrl(result.tokens().get("id_token").asString(), LOGGED_OUT_URI, null)).session(new MockHttpSession()))
                .andExpect(status().is3xxRedirection());
        assertSession(result.asid(), "REVOKED", "LOGOUT");
    }

    @Test
    @DisplayName("登入服務自己的 POST /logout：撤銷目前的 Session，登入頁顯示已登出")
    void formLogoutRevokesTheSession() throws Exception {
        createUser("form-logout", null);
        LoggedIn result = logInAndExchangeCode("form-logout");
        mockMvc.perform(post("/logout").session(result.browser()).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?logout"));
        assertSession(result.asid(), "REVOKED", "LOGOUT");
        String page = mockMvc.perform(get("/login?logout").header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("您已登出");
    }

    @Test
    @DisplayName("帳號頁：未登入時導向登入頁")
    void accountPageRequiresLogin() throws Exception {
        mockMvc.perform(get("/jacky917/account").accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
    }

    @Test
    @DisplayName("帳號頁列出登入中的裝置並標示目前的裝置；登出其他裝置後，該裝置的瀏覽器與 Refresh Token 都失效")
    void accountPageLogsOutAnotherDevice() throws Exception {
        createUser("two-devices", "Two Devices");
        LoggedIn laptop = logInAndExchangeCode("two-devices");
        LoggedIn phone = logInAndExchangeCode("two-devices");
        String page = mockMvc.perform(get("/jacky917/account").session(laptop.browser())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("Two Devices").contains("/jacky917/account/sessions/" + laptop.asid() + "/logout")
                .contains("/jacky917/account/sessions/" + phone.asid() + "/logout");
        assertThat(page.split("目前的裝置", -1)).as("只有一個裝置被標示為目前的裝置").hasSize(2);

        mockMvc.perform(post("/jacky917/account/sessions/{id}/logout", phone.asid()).session(laptop.browser()).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account"));
        assertSession(phone.asid(), "REVOKED", "LOGOUT");
        assertSession(laptop.asid(), "ACTIVE", null);
        assertRefreshRefused(phone);
        mockMvc.perform(get("/jacky917/account").session(phone.browser()).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
    }

    @Test
    @DisplayName("帳號頁：登出目前的裝置會結束瀏覽器的登入")
    void accountPageLogsOutThisDevice() throws Exception {
        createUser("this-device", null);
        LoggedIn result = logInAndExchangeCode("this-device");
        mockMvc.perform(post("/jacky917/account/sessions/{id}/logout", result.asid()).session(result.browser()).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?logout"));
        assertSession(result.asid(), "REVOKED", "LOGOUT");
        assertThat(result.browser().isInvalid()).isTrue();
    }

    @Test
    @DisplayName("帳號頁：不能登出其他使用者的 Session（404）")
    void cannotLogOutSomeoneElsesSession() throws Exception {
        createUser("attacker", null);
        createUser("victim", null);
        LoggedIn attacker = logInAndExchangeCode("attacker");
        LoggedIn victim = logInAndExchangeCode("victim");
        mockMvc.perform(post("/jacky917/account/sessions/{id}/logout", victim.asid()).session(attacker.browser()).with(csrf()))
                .andExpect(status().isNotFound());
        assertSession(victim.asid(), "ACTIVE", null);
    }

    @Test
    @DisplayName("帳號頁：沒有 CSRF token 的登出請求被拒絕")
    void logoutRequiresCsrf() throws Exception {
        createUser("csrf-device", null);
        LoggedIn result = logInAndExchangeCode("csrf-device");
        mockMvc.perform(post("/jacky917/account/sessions/{id}/logout", result.asid()).session(result.browser()))
                .andExpect(status().isForbidden());
        assertSession(result.asid(), "ACTIVE", null);
    }

    @Test
    @DisplayName("帳號頁：登出所有裝置（LOGOUT_ALL），包含目前的瀏覽器")
    void logOutAllDevices() throws Exception {
        createUser("all-devices", null);
        LoggedIn laptop = logInAndExchangeCode("all-devices");
        LoggedIn phone = logInAndExchangeCode("all-devices");
        mockMvc.perform(post("/jacky917/account/logout-all").session(laptop.browser()).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?logout"));
        assertSession(laptop.asid(), "REVOKED", "LOGOUT_ALL");
        assertSession(phone.asid(), "REVOKED", "LOGOUT_ALL");
        assertRefreshRefused(laptop);
        assertRefreshRefused(phone);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE event_type = 'LOGOUT' AND user_id = :user")
                .param("user", laptop.userId()).query(Integer.class).single()).isEqualTo(2);
    }

    /**
     * 以 query string 傳送參數：登出端點的 GET 請求只讀取 query string（MockMvc 的 param() 不會放進 query string）。
     */
    private static URI logoutUrl(String idTokenHint, String postLogoutRedirectUri, String state) {
        UriComponentsBuilder url = UriComponentsBuilder.fromPath("/connect/logout")
                .queryParam("id_token_hint", idTokenHint)
                .queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
        if (state != null) {
            url.queryParam("state", state);
        }
        return url.encode().build().toUri();
    }
}
