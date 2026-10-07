package jacky917.security.autoconfigure.integration;

import jacky917.security.annotations.RequirePerm;
import jacky917.security.annotations.RequireRole;
import jacky917.security.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 驗證 docs/limitations.md 中描述的行為（錯誤回應格式、放行路徑、註解組合限制）。
 */
@SpringBootTest(
        classes = SecurityBehaviorIntegrationTest.TestApplication.class,
        properties = "jacky917.security.permit-all-patterns=/public/**"
)
@AutoConfigureMockMvc
@DisplayName("安全行為與限制整合測試")
class SecurityBehaviorIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("未帶 token：401 JSON + WWW-Authenticate: Bearer（Spring Security 7 另帶 resource_metadata）")
    void missingTokenReturnsJson401() throws Exception {
        mockMvc.perform(get("/secure"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")))
                .andExpect(header().string("WWW-Authenticate", containsString("resource_metadata=")))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.errorCode").value("Unauthorized"))
                .andExpect(jsonPath("$.path").value("/secure"));
    }

    @Test
    @DisplayName("Spring Security 7：RFC 9728 protected resource metadata 端點可匿名存取")
    void protectedResourceMetadataIsPublic() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-protected-resource"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resource").exists())
                .andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"));
    }

    @Test
    @DisplayName("token 無效：同樣回傳 401 JSON，WWW-Authenticate 帶 invalid_token")
    void invalidTokenReturnsJson401() throws Exception {
        mockMvc.perform(get("/secure").header("Authorization", "Bearer bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("放行路徑：不帶 token 可存取，但帶了無效 token 仍回 401")
    void permitAllPathStillRejectsInvalidToken() throws Exception {
        mockMvc.perform(get("/public/ping")).andExpect(status().isOk());
        mockMvc.perform(get("/public/ping").header("Authorization", "Bearer bad"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("放行路徑上的方法級註解仍會生效（匿名呼叫回 401）")
    void methodSecurityStillAppliesOnPermitAllPath() throws Exception {
        mockMvc.perform(get("/public/admin")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("權限不足：403 JSON")
    void insufficientAuthorityReturnsJson403() throws Exception {
        mockMvc.perform(get("/secure/admin").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.errorCode").value("Forbidden"));
    }

    @Test
    @DisplayName("類別與方法都有註解時，只看方法層級（不會合併）")
    void methodLevelAnnotationOverridesClassLevel() throws Exception {
        mockMvc.perform(get("/class-level/method").with(jwt().authorities(new SimpleGrantedAuthority("PERM_x"))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("同一方法疊加兩個 @PreAuthorize 類註解會在呼叫時拋出例外")
    void stackingPreAuthorizeAnnotationsFails() {
        assertThatThrownBy(() -> mockMvc.perform(get("/stacked")
                .with(jwt().authorities(new SimpleGrantedAuthority("PERM_x"), new SimpleGrantedAuthority("ROLE_A")))))
                .hasRootCauseInstanceOf(AnnotationConfigurationException.class);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({Jacky917SecurityAutoConfiguration.class, DemoController.class, ClassLevelController.class})
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> {
                if ("bad".equals(token)) {
                    throw new BadJwtException("bad token");
                }
                return Jwt.withTokenValue(token).header("alg", "none").claim("sub", "test-user").build();
            };
        }
    }

    @RestController
    static class DemoController {
        @GetMapping("/secure")
        public String secure() {
            return "ok";
        }

        @GetMapping("/public/ping")
        public String ping() {
            return "ok";
        }

        @RequireRole("ADMIN")
        @GetMapping("/public/admin")
        public String publicAdmin() {
            return "ok";
        }

        @RequireRole("ADMIN")
        @GetMapping("/secure/admin")
        public String secureAdmin() {
            return "ok";
        }

        @RequirePerm("x")
        @PreAuthorize("hasRole('A')")
        @GetMapping("/stacked")
        public String stacked() {
            return "ok";
        }
    }

    @RestController
    @RequireRole("ADMIN")
    static class ClassLevelController {
        @RequirePerm("x")
        @GetMapping("/class-level/method")
        public String method() {
            return "ok";
        }
    }
}
