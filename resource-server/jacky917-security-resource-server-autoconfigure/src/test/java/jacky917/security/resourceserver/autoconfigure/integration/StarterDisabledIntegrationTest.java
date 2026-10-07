package jacky917.security.resourceserver.autoconfigure.integration;

import jacky917.security.annotations.RequirePerm;
import jacky917.security.annotations.RequireRole;
import jacky917.security.annotations.RequireScope;
import jacky917.security.resourceserver.autoconfigure.config.Jacky917AuthorityEvaluatorAutoConfiguration;
import jacky917.security.resourceserver.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import jacky917.security.resourceserver.autoconfigure.methodsecurity.Jacky917AuthorityEvaluator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 停用 Starter（{@code jacky917.security.enabled=false}）或非 Servlet 應用程式時，
 * {@code @Require*} 註解所需的 bean 仍然存在：應用程式自行啟用方法級授權時，註解照常判斷，
 * 不會因找不到 {@code jacky917AuthorityEvaluator} 而回傳 500。
 */
@DisplayName("停用 Starter 時的註解行為整合測試")
class StarterDisabledIntegrationTest {

    @Nested
    @SpringBootTest(
            classes = TestApplication.class,
            properties = {
                    "jacky917.security.enabled=false",
                    "jacky917.security.jwt.prefix.role=R_"
            }
    )
    @AutoConfigureMockMvc
    @DisplayName("enabled=false，應用程式自行啟用方法級授權")
    class DisabledWithOwnMethodSecurity {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ApplicationContext context;

        @Test
        @DisplayName("Starter 的 filter chain 未建立")
        void starterFilterChainIsNotCreated() {
            assertThat(context.getBeansOfType(SecurityFilterChain.class)).doesNotContainKey("jacky917SecurityFilterChain");
        }

        @Test
        @DisplayName("@RequireRole 照常判斷並跟隨設定的前綴（200／403，不是 500）")
        void requireRoleStillWorks() throws Exception {
            mockMvc.perform(get("/role").with(jwt().authorities(new SimpleGrantedAuthority("R_ADMIN")))).andExpect(status().isOk());
            mockMvc.perform(get("/role").with(jwt().authorities(new SimpleGrantedAuthority("R_USER")))).andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("@RequirePerm／@RequireScope 照常判斷")
        void requirePermAndScopeStillWork() throws Exception {
            mockMvc.perform(get("/perm").with(jwt().authorities(new SimpleGrantedAuthority("PERM_order:read")))).andExpect(status().isOk());
            mockMvc.perform(get("/perm").with(jwt().authorities(new SimpleGrantedAuthority("PERM_order:write")))).andExpect(status().isForbidden());
            mockMvc.perform(get("/scope").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_profile")))).andExpect(status().isOk());
            mockMvc.perform(get("/scope").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_email")))).andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("非 Web 應用程式")
    class NonWebApplication {

        private final ApplicationContextRunner runner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        Jacky917SecurityAutoConfiguration.class,
                        Jacky917AuthorityEvaluatorAutoConfiguration.class
                ));

        @Test
        @DisplayName("註解所需的 bean 存在，filter chain 不存在")
        void evaluatorBeansExistWithoutFilterChain() {
            runner.run(context -> {
                assertThat(context).hasBean("jacky917AuthorityEvaluator");
                assertThat(context).hasSingleBean(AnnotationTemplateExpressionDefaults.class);
                assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
            });
        }

        @Test
        @DisplayName("應用程式自訂同名 evaluator 時，預設的 evaluator 不建立")
        void customEvaluatorBacksOff() {
            Jacky917AuthorityEvaluator custom = new Jacky917AuthorityEvaluator();
            runner.withBean("jacky917AuthorityEvaluator", Jacky917AuthorityEvaluator.class, () -> custom)
                    .run(context -> assertThat(context.getBean("jacky917AuthorityEvaluator")).isSameAs(custom));
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EnableMethodSecurity
    @Import(DemoController.class)
    static class TestApplication {
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
    }
}
