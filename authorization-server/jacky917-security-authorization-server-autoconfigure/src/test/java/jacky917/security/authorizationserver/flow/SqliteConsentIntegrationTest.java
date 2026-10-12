package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@DisplayName("同意畫面整合測試（SQLite）")
class SqliteConsentIntegrationTest extends AbstractConsentIntegrationTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
    }
}
