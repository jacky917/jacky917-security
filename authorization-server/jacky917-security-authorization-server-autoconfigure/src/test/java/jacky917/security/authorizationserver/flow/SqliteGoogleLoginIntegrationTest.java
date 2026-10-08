package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DisplayName("Google 登入整合測試（SQLite）")
class SqliteGoogleLoginIntegrationTest extends AbstractGoogleLoginIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
        provider(registry);
    }
}
