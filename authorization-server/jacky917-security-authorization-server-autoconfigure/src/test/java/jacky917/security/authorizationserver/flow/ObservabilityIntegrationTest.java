package jacky917.security.authorizationserver.flow;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jacky917.security.authorizationserver.maintenance.DataCleanupEvent;
import jacky917.security.authorizationserver.observability.SigningKeyHealthIndicator;
import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Metrics 與健康檢查（詳細設計 §8.2、§8.4）：以實際的登入、刷新與重用驗證每個 metric。只在 SQLite 上執行。
 */
@DisplayName("Metrics 與健康檢查整合測試（SQLite）")
@Import(ObservabilityIntegrationTest.Registry.class)
class ObservabilityIntegrationTest extends AbstractFlowIntegrationTest {

    @Autowired
    MeterRegistry registry;

    @Autowired
    SigningKeyHealthIndicator signingKeyHealth;

    @Autowired
    ApplicationEventPublisher events;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
    }

    @Test
    @DisplayName("登入、簽發、刷新、併發與重用、清理都計入對應的 metric；gauge 讀取資料庫")
    void countsEverything() throws Exception {
        createUser("metrics-user", null);
        LoggedIn result = logInAndExchangeCode("metrics-user");
        assertThat(count("jacky917.as.login", "idp", "local", "result", "success")).isGreaterThanOrEqualTo(1);
        assertThat(count("jacky917.as.token.issued", "grant_type", "authorization_code", "client_id", "web-bff"))
                .isGreaterThanOrEqualTo(1);
        // gauge 在讀取時查詢資料庫（之後的重用偵測會撤銷這個 Session）
        assertThat(registry.get("jacky917.as.session.active").gauge().value()).isGreaterThanOrEqualTo(1);
        assertThat(registry.get("jacky917.as.signing_key.age").gauge().value()).isBetween(0.0, 1.0);

        String old = result.tokens().get("refresh_token").asString();
        JsonNode refreshed = refresh(old);
        assertThat(count("jacky917.as.token.issued", "grant_type", "refresh_token", "client_id", "web-bff"))
                .isGreaterThanOrEqualTo(1);
        assertRefreshRefused(old);
        assertThat(count("jacky917.as.refresh.grace_rejected", "client_id", "web-bff")).isEqualTo(1);
        clock.advance(Duration.ofSeconds(31));
        assertRefreshRefused(old);
        assertThat(count("jacky917.as.refresh.reuse_detected", "client_id", "web-bff")).isEqualTo(1);
        assertThat(count("jacky917.as.refresh.rejected", "reason", "concurrent")).isEqualTo(1);
        assertThat(refreshed.has("access_token")).isTrue();

        events.publishEvent(new DataCleanupEvent("authorizations", 3));
        assertThat(count("jacky917.as.cleanup.deleted", "table", "authorizations")).isEqualTo(3);
    }

    @Test
    @DisplayName("登入失敗依原因計數")
    void countsLoginFailures() throws Exception {
        double before = count("jacky917.as.login", "idp", "local", "result", "unknown_user");
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/login")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
                .param("username", "nobody-for-metrics").param("password", "wrong password!"));
        assertThat(count("jacky917.as.login", "idp", "local", "result", "unknown_user")).isEqualTo(before + 1);
    }

    @Test
    @DisplayName("健康檢查：有 ACTIVE 金鑰時為 UP，詳細資料有 kid，沒有金鑰內容")
    void signingKeyHealth() {
        var health = signingKeyHealth.health(true);
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsKeys("kid", "algorithm", "ageDays", "rotationOverdue")
                .doesNotContainKeys("privateKey", "publicKey");
    }

    private double count(String name, String... tags) {
        var counter = registry.find(name).tags(tags).counter();
        return counter == null ? 0 : counter.count();
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Registry {
        @Bean
        SimpleMeterRegistry simpleMeterRegistry() {
            return new SimpleMeterRegistry();
        }
    }
}
