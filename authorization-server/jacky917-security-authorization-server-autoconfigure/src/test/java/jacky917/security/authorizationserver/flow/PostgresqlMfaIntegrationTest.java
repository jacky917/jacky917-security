package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DisplayName("兩步驟驗證整合測試（PostgreSQL）")
class PostgresqlMfaIntegrationTest extends AbstractMfaIntegrationTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.POSTGRESQL);
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> "postgres");
    }
}
