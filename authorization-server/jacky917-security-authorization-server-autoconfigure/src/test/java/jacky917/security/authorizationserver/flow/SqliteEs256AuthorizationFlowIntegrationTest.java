package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

/**
 * 以 ES256 簽章金鑰跑完整的授權流程：Spring Authorization Server 對 Access Token 一律要求 RS256，
 * encoder 必須改用目前金鑰的演算法，否則每一次簽發都會失敗。
 */
@DisplayName("授權碼流程整合測試（SQLite、ES256 金鑰）")
@TestPropertySource(properties = "jacky917.security.authorization-server.keys.algorithm=ES256")
class SqliteEs256AuthorizationFlowIntegrationTest extends AbstractAuthorizationFlowIntegrationTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
    }
}
