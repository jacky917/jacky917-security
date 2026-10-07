package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DisplayName("Google 登入整合測試（PostgreSQL）")
class PostgresqlGoogleLoginIntegrationTest extends AbstractGoogleLoginIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.POSTGRESQL);
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> "postgres");
        provider(registry);
    }
}
