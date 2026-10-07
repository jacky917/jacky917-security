package jacky917.security.resourceserver.autoconfigure.integration;

import jacky917.security.annotations.RequireAll;
import jacky917.security.annotations.RequireAny;
import jacky917.security.annotations.RequirePerm;
import jacky917.security.annotations.RequireRole;
import jacky917.security.resourceserver.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
        classes = MethodSecurityAnnotationsIntegrationTest.TestApplication.class,
        properties = {
                "jacky917.security.enabled=true"
        }
)
@AutoConfigureMockMvc
@DisplayName("自訂方法級授權註解整合測試")
class MethodSecurityAnnotationsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("@RequireRole: 具備 ROLE_ADMIN 時回傳 200，否則 403")
    void requireRoleShouldWork() throws Exception {
        mockMvc.perform(get("/annotations/role")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(get("/annotations/role")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("@RequirePerm: 具備 PERM_order:read 時回傳 200，否則 403")
    void requirePermShouldWork() throws Exception {
        mockMvc.perform(get("/annotations/perm")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_order:read")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(get("/annotations/perm")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_order:write")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("@RequireAny(OR): 任一權限符合即 200")
    void requireAnyShouldWork() throws Exception {
        mockMvc.perform(get("/annotations/any")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_order:read")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(get("/annotations/any")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(get("/annotations/any")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("@RequireAll(AND): 缺少任一權限即 403")
    void requireAllShouldWork() throws Exception {
        mockMvc.perform(get("/annotations/all")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(
                                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                                        new SimpleGrantedAuthority("PERM_order:read")
                                ))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(get("/annotations/all")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({Jacky917SecurityAutoConfiguration.class, AnnotationDemoController.class})
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token)
                    .header("alg", "none")
                    .claim("sub", "test-user")
                    .build();
        }
    }

    @RestController
    static class AnnotationDemoController {
        @RequireRole("ADMIN")
        @GetMapping("/annotations/role")
        public String roleOnly() {
            return "ok";
        }

        @RequirePerm("order:read")
        @GetMapping("/annotations/perm")
        public String permOnly() {
            return "ok";
        }

        @RequireAny("ROLE_ADMIN|PERM_order:read")
        @GetMapping("/annotations/any")
        public String anyRule() {
            return "ok";
        }

        @RequireAll("ROLE_ADMIN|PERM_order:read")
        @GetMapping("/annotations/all")
        public String allRule() {
            return "ok";
        }
    }
}

