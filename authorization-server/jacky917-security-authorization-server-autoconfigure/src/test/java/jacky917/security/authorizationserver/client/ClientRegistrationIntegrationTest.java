package jacky917.security.authorizationserver.client;

import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.core.TrustLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 設定中宣告的 client 在啟動時寫入資料庫：強制 PKCE、輪換 Refresh Token、secret 以 BCrypt 雜湊，
 * 重新啟動時依設定更新；停權的 client 對 Spring Security 而言不存在（T-CLIENT-01 的前半）。
 */
@DisplayName("Client 註冊整合測試（SQLite／PostgreSQL）")
class ClientRegistrationIntegrationTest {

    private static final String PREFIX = "jacky917.security.authorization-server.clients.";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("建立 BFF、批次程式、public client，設定符合設計")
    void registersConfiguredClients(String vendor) {
        withClients(TestDatabases.runner(vendor)).run(context -> {
            assertThat(context).hasNotFailed();
            RegisteredClientRepository clients = context.getBean(RegisteredClientRepository.class);
            PasswordEncoder encoder = context.getBean(PasswordEncoder.class);

            RegisteredClient bff = clients.findByClientId("web-bff");
            assertThat(bff.getClientName()).isEqualTo("Web BFF");
            assertThat(bff.getClientSecret()).startsWith("{bcrypt}");
            assertThat(encoder.matches("bff-secret", bff.getClientSecret())).isTrue();
            assertThat(bff.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            assertThat(bff.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
                    AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
            assertThat(bff.getRedirectUris()).containsExactly("https://app.example.com/login/oauth2/code/jacky917");
            assertThat(bff.getPostLogoutRedirectUris()).containsExactly("https://app.example.com/");
            assertThat(bff.getScopes()).containsExactlyInAnyOrder("openid", "profile", "email");
            assertThat(bff.getClientSettings().isRequireProofKey()).isTrue();
            assertThat(bff.getClientSettings().isRequireAuthorizationConsent()).isFalse();
            assertThat(bff.getTokenSettings().isReuseRefreshTokens()).isFalse();
            assertThat(bff.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
            assertThat(bff.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(14));
            assertThat(bff.getTokenSettings().getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofMinutes(1));
            assertThat(bff.getTokenSettings().getIdTokenSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);

            RegisteredClient batch = clients.findByClientId("report-batch");
            assertThat(batch.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
            assertThat(batch.getScopes()).containsExactly("report.generate");

            RegisteredClient mobile = clients.findByClientId("mobile-app");
            assertThat(mobile.getClientSecret()).isNull();
            assertThat(mobile.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
            assertThat(mobile.getClientSettings().isRequireProofKey()).isTrue();

            ClientProfile profile = context.getBean(ClientProfileRepository.class).find(bff.getId()).orElseThrow();
            assertThat(profile.trustLevel()).isEqualTo(TrustLevel.FIRST_PARTY);
            assertThat(profile.status()).isEqualTo(ClientStatus.ACTIVE);
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("重新啟動：依設定更新；secret 相同時不重新雜湊，修改後換成新的雜湊")
    void restartUpdatesClients(String vendor) {
        String url = TestDatabases.newDatabaseUrl(vendor);
        String[] firstHash = new String[2];
        withClients(TestDatabases.runner(vendor, url)).run(context -> {
            RegisteredClient bff = context.getBean(RegisteredClientRepository.class).findByClientId("web-bff");
            firstHash[0] = bff.getId();
            firstHash[1] = bff.getClientSecret();
        });

        withClients(TestDatabases.runner(vendor, url))
                .withPropertyValues(PREFIX + "web-bff.redirect-uris=https://new.example.com/callback")
                .run(context -> {
                    RegisteredClient bff = context.getBean(RegisteredClientRepository.class).findByClientId("web-bff");
                    assertThat(bff.getId()).isEqualTo(firstHash[0]);
                    assertThat(bff.getRedirectUris()).containsExactly("https://new.example.com/callback");
                    assertThat(bff.getClientSecret()).isEqualTo(firstHash[1]);
                    assertThat(context.getBean(JdbcClient.class).sql("SELECT COUNT(*) FROM oauth2_registered_client")
                            .query(Integer.class).single()).isEqualTo(3);
                });

        withClients(TestDatabases.runner(vendor, url))
                .withPropertyValues(PREFIX + "web-bff.secret=rotated-secret")
                .run(context -> {
                    RegisteredClient bff = context.getBean(RegisteredClientRepository.class).findByClientId("web-bff");
                    assertThat(bff.getClientSecret()).isNotEqualTo(firstHash[1]);
                    assertThat(context.getBean(PasswordEncoder.class).matches("rotated-secret", bff.getClientSecret()))
                            .isTrue();
                });
    }

    @Test
    @DisplayName("confidential client 沒有 secret 時啟動失敗，訊息指出要設定的屬性")
    void confidentialClientWithoutSecretFailsStartup() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues(PREFIX + "web-bff.redirect-uris=https://app.example.com/callback")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("Client web-bff requires a secret")
                        .hasStackTraceContaining("${WEB_BFF_SECRET}"));
    }

    @Test
    @DisplayName("停權的 client 查不到（token 端點因此回 invalid_client）；重新啟動不會解除停權")
    void suspendedClientIsHidden() {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        withClients(TestDatabases.runner(TestDatabases.SQLITE, url)).run(context -> {
            RegisteredClientRepository clients = context.getBean(RegisteredClientRepository.class);
            String id = clients.findByClientId("web-bff").getId();
            context.getBean(JdbcClient.class).sql("UPDATE client_profile SET status = 'SUSPENDED' WHERE registered_client_id = :id")
                    .param("id", id).update();
            assertThat(clients.findByClientId("web-bff")).isNull();
            assertThat(clients.findById(id)).isNull();
            assertThat(clients.findByClientId("report-batch")).isNotNull();
        });
        withClients(TestDatabases.runner(TestDatabases.SQLITE, url)).run(context ->
                assertThat(context.getBean(RegisteredClientRepository.class).findByClientId("web-bff")).isNull());
    }

    private static ApplicationContextRunner withClients(ApplicationContextRunner runner) {
        return runner.withPropertyValues(
                PREFIX + "web-bff.display-name=Web BFF",
                PREFIX + "web-bff.secret=bff-secret",
                PREFIX + "web-bff.redirect-uris=https://app.example.com/login/oauth2/code/jacky917",
                PREFIX + "web-bff.post-logout-redirect-uris=https://app.example.com/",
                PREFIX + "web-bff.scopes=openid,profile,email",
                PREFIX + "report-batch.secret=batch-secret",
                PREFIX + "report-batch.grant-types=client_credentials",
                PREFIX + "report-batch.scopes=report.generate",
                PREFIX + "mobile-app.authentication-method=none",
                PREFIX + "mobile-app.grant-types=authorization_code",
                PREFIX + "mobile-app.redirect-uris=com.example.app:/callback,http://localhost:8080/callback");
    }
}
