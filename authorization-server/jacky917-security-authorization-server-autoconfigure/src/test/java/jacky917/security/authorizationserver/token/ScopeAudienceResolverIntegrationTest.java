package jacky917.security.authorizationserver.token;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code token.audience-strategy: per-scope}（D07-C）：audience 取自 scope 所屬的 API resource。
 */
@DisplayName("依 scope 決定 audience（SQLite／PostgreSQL）")
class ScopeAudienceResolverIntegrationTest {

    private static final RegisteredClient CLIENT = RegisteredClient.withId("client-1").clientId("partner")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://p.example.com/cb")
            .build();

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("scope 所屬的 API resource（去除重複、排序）；沒有任何 scope 屬於 API resource 時使用 token.audience")
    void usesTheApiResourcesOfTheScopes(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            JdbcClient jdbc = context.getBean(JdbcClient.class);
            Timestamp now = Timestamp.from(Instant.now());
            for (String resource : List.of("orders-api", "billing-api")) {
                jdbc.sql("INSERT INTO api_resource (code, name, created_at) VALUES (:code, :code, :now)")
                        .param("code", resource).param("now", now).update();
            }
            for (String[] scope : List.of(new String[]{"orders.read", "orders-api"},
                    new String[]{"orders.write", "orders-api"}, new String[]{"billing.read", "billing-api"})) {
                jdbc.sql("INSERT INTO app_scope (code, api_resource_code, display_name, consent_required, built_in, "
                                + "created_at) VALUES (:code, :resource, :code, :yes, :no, :now)")
                        .param("code", scope[0]).param("resource", scope[1]).param("yes", true).param("no", false)
                        .param("now", now).update();
            }
            ScopeAudienceResolver resolver = new ScopeAudienceResolver(jdbc, List.of("jacky917-api"));

            assertThat(resolver.resolve(CLIENT, Set.of("openid", "orders.read", "orders.write", "billing.read")))
                    .containsExactly("billing-api", "orders-api");
            assertThat(resolver.resolve(CLIENT, Set.of("openid", "orders.read"))).containsExactly("orders-api");
            assertThat(resolver.resolve(CLIENT, Set.of("openid", "profile"))).containsExactly("jacky917-api");
            assertThat(resolver.resolve(CLIENT, Set.of("report.generate"))).as("app_scope 中沒有的 scope")
                    .containsExactly("jacky917-api");
            assertThat(resolver.resolve(CLIENT, Set.of())).containsExactly("jacky917-api");
        });
    }
}
