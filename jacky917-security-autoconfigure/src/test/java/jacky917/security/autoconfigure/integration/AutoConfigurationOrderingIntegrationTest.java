package jacky917.security.autoconfigure.integration;

import jacky917.security.autoconfigure.config.Jacky917SecurityAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 驗證 {@code @AutoConfiguration(beforeName = ...)} 的排序確實生效。
 * <p>
 * 以字串指定類別時，名稱打錯不會有任何錯誤，只會讓 Spring Boot 的預設設定取代 Starter 的設定，
 * 因此必須以測試確認。這裡刻意設定會讓 Spring Boot 建立自己的 {@code JwtAuthenticationConverter} 的屬性。
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
    @Import(Jacky917SecurityAutoConfiguration.class)
    static class TestApplication {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> Jwt.withTokenValue(token).header("alg", "none").claim("sub", "test-user").build();
        }
    }
}
