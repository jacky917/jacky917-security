package jacky917.demo.bff;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 範例 BFF 不需要登入服務即可啟動；未登入時 API 回 401，登入會前往登入服務並帶 PKCE。
 * 完整的登入流程在 e2e-tests 中驗證。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("範例 BFF")
class BffApplicationTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @DisplayName("首頁公開；未登入時 /me 與 /api/** 回 401")
    void anonymousAccess() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
        mockMvc.perform(get("/me")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/secure/me")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("登入前往登入服務的授權端點，並使用 PKCE")
    void loginRedirectsToAuthorizationServerWithPkce() throws Exception {
        String location = mockMvc.perform(get("/oauth2/authorization/jacky917"))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(location).startsWith("http://localhost:9000/oauth2/authorize")
                .contains("client_id=web-bff").contains("code_challenge=").contains("code_challenge_method=S256");
    }
}
