package jacky917.security.resourceserver.autoconfigure.integration;

import jacky917.security.resourceserver.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 驗證錯誤回應改用應用程式的 Jackson 3 {@code JsonMapper}，因此 {@code spring.jackson.*} 設定會生效。
 */
@SpringBootTest(
        classes = ErrorResponseJsonMapperIntegrationTest.TestApplication.class,
        properties = "spring.jackson.serialization.indent-output=true"
)
@AutoConfigureMockMvc
@DisplayName("錯誤回應 JSON 序列化整合測試")
class ErrorResponseJsonMapperIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("spring.jackson.serialization.indent-output 會套用到 401 回應")
    void errorBodyUsesApplicationJsonMapper() throws Exception {
        String body = mockMvc.perform(get("/anything"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(body).contains("\n").contains("\"status\" : 401");
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Jacky917SecurityAutoConfiguration.class)
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token).header("alg", "none").claim("sub", "test-user").build();
        }
    }
}
