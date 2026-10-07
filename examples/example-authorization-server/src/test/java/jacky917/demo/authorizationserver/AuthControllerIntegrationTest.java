package jacky917.demo.authorizationserver;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Demo Auth Server Token 簽發整合測試")
class AuthControllerIntegrationTest {

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("以正確帳密可簽發含指定 claims 的 JWT")
    void shouldIssueJwtWhenCredentialIsValid() throws Exception {
        String requestBody = """
                {
                  "username": "alice",
                  "password": "password",
                  "roles": ["A"],
                  "permissions": ["bb", "clip:read"],
                  "scp": ["profile.read"],
                  "sid": "sid-e2e",
                  "expiresInSeconds": 600
                }
                """;

        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .contentType(APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        JsonNode node = JSON_MAPPER.readTree(response);
        String accessToken = node.get("accessToken").asString();

        SignedJWT jwt = SignedJWT.parse(accessToken);
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).contains("A");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("permissions")).contains("bb", "clip:read");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("scp")).contains("profile.read");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("sid")).isEqualTo("sid-e2e");
    }

    @Test
    @DisplayName("密碼錯誤時回傳 401")
    void shouldReturn401WhenPasswordInvalid() throws Exception {
        String requestBody = """
                {
                  "username": "alice",
                  "password": "wrong-password"
                }
                """;

        mockMvc.perform(post("/oauth2/token")
                        .contentType(APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}

