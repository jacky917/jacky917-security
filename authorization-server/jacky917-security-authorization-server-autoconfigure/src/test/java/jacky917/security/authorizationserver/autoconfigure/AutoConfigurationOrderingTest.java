package jacky917.security.authorizationserver.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * {@code beforeName} 以字串指定 Spring Boot 的自動配置，名稱打錯或 Spring Boot 搬移類別時不會有任何錯誤，
 * Spring Boot 的預設 filter chain、UserDetailsService、JWKSource 就會在本配置之前建立。
 */
@DisplayName("Authorization Server 自動配置排序")
class AutoConfigurationOrderingTest {

    @Test
    @DisplayName("beforeName 列出的每個類別都存在")
    void beforeNameClassesExist() {
        AutoConfiguration annotation = AuthorizationServerAutoConfiguration.class.getAnnotation(AutoConfiguration.class);
        assertThat(annotation.beforeName()).isNotEmpty();
        for (String className : annotation.beforeName()) {
            assertThatCode(() -> Class.forName(className)).as("beforeName 中的類別不存在：%s", className)
                    .doesNotThrowAnyException();
        }
    }
}
