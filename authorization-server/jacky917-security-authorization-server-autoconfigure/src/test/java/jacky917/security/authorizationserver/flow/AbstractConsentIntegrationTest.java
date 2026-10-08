package jacky917.security.authorizationserver.flow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 第三方 client 的同意畫面與帳號頁的已授權應用程式（第 3、4 階段設計 §6.2、§6.3）。第三方 client {@code partner}
 * 定義在 {@link AbstractFlowIntegrationTest} 的設定中。
 */
abstract class AbstractConsentIntegrationTest extends AbstractFlowIntegrationTest {

    @Test
    @DisplayName("同意畫面：列出要同意的 scope；只同意勾選的 scope；之後不再詢問；新增 scope 時只詢問新的；稽核（T-CONSENT-01）")
    void asksForConsentOnce() throws Exception {
        String userId = createUser("consenting-user", null);
        MockHttpSession browser = logIn("consenting-user", "openid profile email");
        String verifier = randomVerifier();
        MultiValueMap<String, String> consent = consentRequest(browser, "openid profile email", verifier);

        MvcResult page = mockMvc.perform(get("/oauth2/consent").session(browser).params(consent)
                .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW")).andExpect(status().isOk()).andReturn();
        String html = page.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(html).contains("Partner App 要求存取您的帳號").contains("基本資料").contains("value=\"email\"")
                .contains("https://partner.example.com/privacy").doesNotContain("value=\"openid\" checked");

        // 只勾選 profile
        String callback = decide(browser, consent, "profile");
        MultiValueMap<String, String> query = UriComponentsBuilder.fromUriString(callback).build().getQueryParams();
        assertThat(callback).startsWith(PARTNER_REDIRECT_URI);
        assertThat(query.getFirst("state")).isEqualTo("partner-state");
        JsonNode tokens = exchange(query.getFirst("code"), verifier);
        assertThat(tokens.get("scope").asString().split(" ")).containsExactlyInAnyOrder("openid", "profile");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'CONSENT_GRANTED'")
                .param("user", userId).query(Integer.class).single()).isEqualTo(1);

        // 已同意的 scope 不再詢問
        assertThat(authorize(browser, "openid profile", randomVerifier())).startsWith(PARTNER_REDIRECT_URI);
        // 新增 email：只詢問 email，profile 列在先前已允許
        String again = authorize(browser, "openid profile email", randomVerifier());
        assertThat(again).contains("/oauth2/consent");
        String second = mockMvc.perform(get(URI.create(again)).session(browser).header(HttpHeaders.ACCEPT_LANGUAGE,
                "zh-TW")).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(second).contains("value=\"email\"").doesNotContain("value=\"profile\"").contains("您先前已允許");
    }

    @Test
    @DisplayName("拒絕：client 收到 access_denied，不建立同意紀錄")
    void deniesConsent() throws Exception {
        createUser("denying-user", null);
        MockHttpSession browser = logIn("denying-user", "openid profile");
        MultiValueMap<String, String> consent = consentRequest(browser, "openid profile", randomVerifier());
        String callback = decide(browser, consent);
        assertThat(callback).startsWith(PARTNER_REDIRECT_URI).contains("error=access_denied");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM oauth2_authorization_consent WHERE principal_name = "
                + "(SELECT id FROM app_user WHERE username = 'denying-user')").query(Integer.class).single()).isZero();
    }

    @Test
    @DisplayName("帳號頁列出已授權的應用程式；撤回後 Refresh Token 失效、稽核，下一次授權再次詢問（T-CONSENT-02）")
    void revokesFromTheAccountPage() throws Exception {
        String userId = createUser("revoking-user", null);
        MockHttpSession browser = logIn("revoking-user", "openid profile");
        String verifier = randomVerifier();
        MultiValueMap<String, String> consent = consentRequest(browser, "openid profile", verifier);
        String callback = decide(browser, consent, "profile");
        JsonNode tokens = exchange(UriComponentsBuilder.fromUriString(callback).build().getQueryParams()
                .getFirst("code"), verifier);

        String account = mockMvc.perform(get("/jacky917/account").session(browser)
                .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW")).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
        assertThat(account).contains("已授權的應用程式").contains("Partner App").contains("基本資料")
                .contains("/jacky917/account/apps/partner/revoke");

        mockMvc.perform(post("/jacky917/account/apps/partner/revoke").session(browser).with(csrf()))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account?notice=app_revoked"));
        assertThat(jdbc.sql("SELECT COUNT(*) FROM oauth2_authorization_consent WHERE principal_name = :user")
                .param("user", userId).query(Integer.class).single()).isZero();
        mockMvc.perform(post("/oauth2/token").with(httpBasic("partner", "partner-secret"))
                        .param("grant_type", "refresh_token").param("refresh_token", tokens.get("refresh_token").asString()))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'CONSENT_REVOKED'")
                .param("user", userId).query(Integer.class).single()).isEqualTo(1);
        assertThat(authorize(browser, "openid profile", randomVerifier())).contains("/oauth2/consent");
        assertThat(mockMvc.perform(get("/jacky917/account").session(browser)).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8)).doesNotContain("/jacky917/account/apps/partner/revoke");
    }

    // ---- 共用工具 ----

    /**
     * 以 partner 的授權請求開始，登入後回傳已登入的瀏覽器。
     */
    MockHttpSession logIn(String username, String scope) throws Exception {
        MvcResult toLogin = mockMvc.perform(get(partnerAuthorizeUrl(scope, challenge(randomVerifier())))
                        .session(new MockHttpSession()).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login")).andReturn();
        MockHttpSession browser = (MockHttpSession) toLogin.getRequest().getSession();
        mockMvc.perform(post("/login").session(browser).param("username", username).param("password", PASSWORD)
                .param("_csrf", csrfToken(browser))).andExpect(status().is3xxRedirection());
        return browser;
    }

    /**
     * 發出授權請求，回傳重導的位置（同意畫面或 client 的 callback）。
     */
    String authorize(MockHttpSession browser, String scope, String verifier) throws Exception {
        return mockMvc.perform(get(partnerAuthorizeUrl(scope, challenge(verifier))).session(browser))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    /**
     * 發出授權請求並確認被導向同意畫面，回傳同意畫面的參數（client_id、scope、state）。
     */
    MultiValueMap<String, String> consentRequest(MockHttpSession browser, String scope, String verifier)
            throws Exception {
        String location = authorize(browser, scope, verifier);
        assertThat(location).contains("/oauth2/consent");
        return UriComponentsBuilder.fromUriString(location).build(true).getQueryParams().entrySet().stream()
                .collect(org.springframework.util.LinkedMultiValueMap::new, (map, entry) -> entry.getValue()
                        .forEach(value -> map.add(entry.getKey(), java.net.URLDecoder.decode(value,
                                StandardCharsets.UTF_8))), org.springframework.util.LinkedMultiValueMap::putAll);
    }

    /**
     * 在同意畫面送出決定：勾選的 scope；不帶 scope 表示拒絕。回傳導向 client 的位置。
     */
    String decide(MockHttpSession browser, MultiValueMap<String, String> consent, String... scopes) throws Exception {
        var request = post("/oauth2/authorize").session(browser)
                .param("client_id", consent.getFirst("client_id")).param("state", consent.getFirst("state"));
        if (scopes.length > 0) {
            request.param("scope", "openid");
            request.param("scope", scopes);
        }
        return mockMvc.perform(request).andExpect(status().is3xxRedirection()).andReturn().getResponse()
                .getRedirectedUrl();
    }

    JsonNode exchange(String code, String verifier) throws Exception {
        return tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("partner", "partner-secret"))
                .param("grant_type", "authorization_code").param("code", code)
                .param("redirect_uri", PARTNER_REDIRECT_URI).param("code_verifier", verifier)));
    }

    static URI partnerAuthorizeUrl(String scope, String challenge) {
        return UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "partner")
                .queryParam("redirect_uri", PARTNER_REDIRECT_URI)
                .queryParam("scope", scope)
                .queryParam("state", "partner-state")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .encode().build().toUri();
    }
}
