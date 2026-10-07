package jacky917.security.resourceserver.autoconfigure.integration;

import jacky917.security.resourceserver.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * 驗證自動配置的執行順序：Starter 的設定必須優先於 Spring Boot 的安全性自動配置。
 * <p>
 * Spring Boot 排序自動配置時，先依類別名稱的字母順序，再套用
 * {@code before}／{@code after}。{@code jacky917.…} 本來就排在
 * {@code org.springframework.…} 前面，因此即使 {@code beforeName} 寫錯，
 * 目前的行為也不會出錯；{@code beforeName} 是避免日後套件名稱改變時失去
 * 優先順序的保險。以字串指定的類別名稱打錯時不會有任何錯誤，所以由
 * {@link #beforeNameClassesExist()} 確認每個類別都存在。
 * <p>
 * 測試應用程式只使用 {@code @EnableAutoConfiguration}（不直接 {@code @Import}），
 * 讓 Starter 經由 {@code AutoConfiguration.imports} 載入，與實際使用者的情況相同。
 */
@SpringBootTest(
        classes = AutoConfigurationOrderingIntegrationTest.TestApplication.class,
        properties = {
                "spring.security.oauth2.resourceserver.jwt.principal-claim-name=email",
                "spring.security.oauth2.resourceserver.jwt.authority-prefix=BOOT_"
        }
)
@DisplayName("自動配置排序整合測試")
class AutoConfigurationOrderingIntegrationTest {

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("beforeName 列出的每個類別都存在（名稱打錯或 Spring Boot 搬移類別時會失敗）")
    void beforeNameClassesExist() {
        AutoConfiguration annotation = Jacky917SecurityAutoConfiguration.class.getAnnotation(AutoConfiguration.class);
        assertThat(annotation.beforeName()).isNotEmpty();
        for (String className : annotation.beforeName()) {
            assertThatCode(() -> Class.forName(className))
                    .as("beforeName 中的類別不存在：%s", className)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("只有 Starter 的 SecurityFilterChain，Spring Boot 的預設 filter chain 未建立")
    void onlyStarterFilterChainExists() {
        Map<String, SecurityFilterChain> chains = context.getBeansOfType(SecurityFilterChain.class);
        assertThat(chains).containsOnlyKeys("jacky917SecurityFilterChain");
    }

    @Test
    @DisplayName("只有 Starter 的 JwtAuthenticationConverter，Spring Boot 依屬性建立的 converter 未建立")
    void onlyStarterJwtConverterExists() {
        Map<String, JwtAuthenticationConverter> converters = context.getBeansOfType(JwtAuthenticationConverter.class);
        assertThat(converters).hasSize(1);

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("sub", "user-1")
                .claim("email", "user@example.com")
                .claim("roles", List.of("ADMIN"))
                .build();
        var authentication = converters.values().iterator().next().convert(jwt);

        // 若使用的是 Spring Boot 的 converter，名稱會是 email、前綴會是 BOOT_
        // Spring Security 7 會另外加入 FACTOR_BEARER（表示以 Bearer Token 驗證），不屬於 Starter 的映射
        assertThat(authentication.getName()).isEqualTo("user-1");
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ADMIN")
                .noneMatch(authority -> authority.startsWith("BOOT_"));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token).header("alg", "none").claim("sub", "test-user").build();
        }
    }
}
