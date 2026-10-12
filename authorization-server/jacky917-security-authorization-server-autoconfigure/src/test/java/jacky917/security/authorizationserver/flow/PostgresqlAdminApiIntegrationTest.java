package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DisplayName("管理 API 整合測試（PostgreSQL）")
class PostgresqlAdminApiIntegrationTest extends AbstractAdminApiIntegrationTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.POSTGRESQL);
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> "postgres");
    }
}
