package jacky917.security.authorizationserver.autoconfigure;

import io.micrometer.core.instrument.MeterRegistry;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.observability.AuthorizationServerMetrics;
import jacky917.security.authorizationserver.observability.SigningKeyHealthIndicator;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Clock;

/**
 * Metrics and health check of the authorization server (detailed design
 * §8.2, §8.4), when the application has Micrometer and Spring Boot's
 * health support (for example {@code spring-boot-starter-actuator}).
 * <p>
 * 應用程式有 Micrometer 與 Spring Boot 的健康檢查（例如
 * {@code spring-boot-starter-actuator}）時，提供 Authorization Server 的 metrics
 * 與健康檢查（詳細設計 §8.2、§8.4）。
 * <p>
 * The health indicator is named {@code signingKey}; turn it off with
 * {@code management.health.signingkey.enabled=false}.
 * <p>
 * 健康檢查的名稱為 {@code signingKey}，可以
 * {@code management.health.signingkey.enabled=false} 關閉。
 *
 * @author Jacky
 * @since 2.1.0
 */
// 類別名稱已對照 Spring Boot 4.1.1 的 jar 確認；升級 Spring Boot 時須重新確認（名稱錯誤時順序設定靜默失效，測試無法發現）
@AutoConfiguration(after = AuthorizationServerAutoConfiguration.class, afterName = {
        "org.springframework.boot.micrometer.metrics.autoconfigure.MetricsAutoConfiguration",
        "org.springframework.boot.micrometer.metrics.autoconfigure.CompositeMeterRegistryAutoConfiguration"
})
@ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class AuthorizationServerObservabilityAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(MeterRegistry.class)
    @ConditionalOnBean({MeterRegistry.class, SigningKeyStore.class})
    static class Metrics {

        @Bean
        @ConditionalOnMissingBean
        AuthorizationServerMetrics jacky917AuthorizationServerMetrics(MeterRegistry registry,
                                                                      RegisteredClientRepository clients,
                                                                      JdbcClient jdbcClient, SigningKeyStore keys,
                                                                      Clock clock) {
            return new AuthorizationServerMetrics(registry, clients, jdbcClient, keys, clock);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(AbstractHealthIndicator.class)
    @ConditionalOnBean(SigningKeyStore.class)
    @ConditionalOnEnabledHealthIndicator("signingkey")
    static class Health {

        @Bean
        @ConditionalOnMissingBean(name = "signingKeyHealthIndicator")
        SigningKeyHealthIndicator signingKeyHealthIndicator(SigningKeyStore keys, AuthorizationServerProperties properties,
                                                            Clock clock) {
            return new SigningKeyHealthIndicator(keys, properties.getKeys().getRotationPeriod(),
                    properties.getKeys().isRotationEnabled(), clock);
        }
    }
}
