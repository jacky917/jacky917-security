package jacky917.security.resourceserver.autoconfigure.integration;

import jacky917.security.annotations.RequirePerm;
import jacky917.security.annotations.RequireRole;
import jacky917.security.annotations.RequireScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 2.0 的行為：單一條件註解跟隨設定的前綴、預設放行路徑只有 health、{@code @Secured} 仍然生效。
 */
@DisplayName("前綴與預設值整合測試（2.0）")
class PrefixAndDefaultsIntegrationTest {

    @Nested
    @SpringBootTest(
            classes = TestApplication.class,
            properties = {
                    "jacky917.security.jwt.prefix.role=R_",
                    "jacky917.security.jwt.prefix.permission=P_",
                    "jacky917.security.jwt.prefix.scope=S_"
            }
    )
    @AutoConfigureMockMvc
    @DisplayName("自訂前綴")
    class CustomPrefixes {

        @Autowired
        private MockMvc mockMvc;

        @Test
        @DisplayName("@RequireRole／@RequirePerm／@RequireScope 使用設定的前綴")
        void annotationsFollowConfiguredPrefixes() throws Exception {
            mockMvc.perform(get("/role").with(jwt().authorities(new SimpleGrantedAuthority("R_ADMIN")))).andExpect(status().isOk());
            mockMvc.perform(get("/perm").with(jwt().authorities(new SimpleGrantedAuthority("P_order:read")))).andExpect(status().isOk());
            mockMvc.perform(get("/scope").with(jwt().authorities(new SimpleGrantedAuthority("S_profile")))).andExpect(status().isOk());
        }

        @Test
        @DisplayName("預設前綴的 authority 在自訂前綴下不再通過")
        void defaultPrefixNoLongerMatches() throws Exception {
            mockMvc.perform(get("/role").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))).andExpect(status().isForbidden());
            mockMvc.perform(get("/perm").with(jwt().authorities(new SimpleGrantedAuthority("PERM_order:read")))).andExpect(status().isForbidden());
            mockMvc.perform(get("/scope").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_profile")))).andExpect(status().isForbidden());
        }
    }

    @Nested
    @SpringBootTest(classes = TestApplication.class)
    @AutoConfigureMockMvc
    @DisplayName("預設值")
    class Defaults {

        @Autowired
        private MockMvc mockMvc;

        @Test
        @DisplayName("Swagger／OpenAPI 路徑預設不再放行")
        void swaggerIsNotPublicByDefault() throws Exception {
            mockMvc.perform(get("/v3/api-docs")).andExpect(status().isUnauthorized());
            mockMvc.perform(get("/swagger-ui/index.html")).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("/actuator/health 預設仍放行（不回 401）")
        void healthIsPublicByDefault() throws Exception {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("@Secured 仍然生效")
        void securedIsStillEnforced() throws Exception {
            mockMvc.perform(get("/secured").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))).andExpect(status().isForbidden());
            mockMvc.perform(get("/secured").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))).andExpect(status().isOk());
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(DemoController.class)
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token).header("alg", "none").claim("sub", "test-user").build();
        }
    }

    @RestController
    static class DemoController {
        @RequireRole("ADMIN")
        @GetMapping("/role")
        public String role() {
            return "ok";
        }

        @RequirePerm("order:read")
        @GetMapping("/perm")
        public String perm() {
            return "ok";
        }

        @RequireScope("profile")
        @GetMapping("/scope")
        public String scope() {
            return "ok";
        }

        @Secured("ROLE_ADMIN")
        @GetMapping("/secured")
        public String secured() {
            return "ok";
        }
    }
}
