package jacky917.demo.resourceserver;

import jacky917.demo.resourceserver.clip.Clip;
import jacky917.demo.resourceserver.clip.ClipRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("demo-resource-server 整合測試")
class DemoResourceServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ClipRepository clipRepository;

    @BeforeEach
    void setUp() {
        clipRepository.deleteAll();
        clipRepository.save(new Clip("demo-001", "Demo Clip", "alice"));
        clipRepository.save(new Clip("private-001", "Private Clip", "bob"));
    }

    @Test
    @DisplayName("public 端點可匿名存取")
    void publicPingShouldReturn200() throws Exception {
        mockMvc.perform(get("/public/ping"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));
    }

    @Test
    @DisplayName("無 token 存取 secure 端點回傳 401 且包含標準 JSON 錯誤欄位")
    void noTokenShouldReturn401() throws Exception {
        mockMvc.perform(get("/secure/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").exists())
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.path").value("/secure/me"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("角色端點：有 ROLE_A 回傳 200，否則 403")
    void roleEndpointShouldValidateAuthorities() throws Exception {
        mockMvc.perform(get("/secure/role-a")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_A"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/role-a")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_B"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("權限端點：有 PERM_bb 回傳 200，否則 403")
    void permEndpointShouldValidateAuthorities() throws Exception {
        mockMvc.perform(get("/secure/perm-bb")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_bb"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/perm-bb")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_other"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("AND 端點：需同時具備 ROLE_A 與 PERM_bb")
    void andEndpointShouldRequireAllAuthorities() throws Exception {
        mockMvc.perform(get("/secure/and")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(
                                        new SimpleGrantedAuthority("ROLE_A"),
                                        new SimpleGrantedAuthority("PERM_bb")
                                )))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/and")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_A"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("OR 端點：ROLE_A 或 PERM_bb 任一符合即可")
    void orEndpointShouldRequireAnyAuthorities() throws Exception {
        mockMvc.perform(get("/secure/or")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_A"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/or")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("PERM_bb"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/or")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(new SimpleGrantedAuthority("ROLE_C"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ABAC 端點：需 PERM_clip:read 且資料庫 ownerId 必須等於 JWT sub")
    void abacEndpointShouldCheckRoleAndClipRule() throws Exception {
        mockMvc.perform(get("/secure/abac/demo-001")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .jwt(jwt -> jwt.subject("alice"))
                                .authorities(new SimpleGrantedAuthority("PERM_clip:read"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure/abac/private-001")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .jwt(jwt -> jwt.subject("alice"))
                                .authorities(new SimpleGrantedAuthority("PERM_clip:read"))))
                .andExpect(status().isForbidden());
    }
}

