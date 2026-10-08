package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.user.NewUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code account-linking.mode=manual-only}：Email 屬於既有帳號時直接拒絕，只能從帳號頁連結（D06-D）。
 */
@DisplayName("帳號連結整合測試（只允許手動連結，SQLite）")
@TestPropertySource(properties = "jacky917.security.authorization-server.account-linking.mode=manual-only")
class ManualOnlyAccountLinkingIntegrationTest extends AbstractGoogleIntegrationTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
        provider(registry);
    }

    @Test
    @DisplayName("已驗證的 Email 屬於既有帳號：/login?error=account_exists，不建立使用者也不保存待確認的連結")
    void verifiedEmailOfExistingAccountIsRejected() throws Exception {
        String email = "manual-" + UUID.randomUUID() + "@example.com";
        users.createUser(new NewUser(null, email, true, "correct horse battery", null, Set.of()));
        int before = jdbc.sql("SELECT COUNT(*) FROM app_user").query(Integer.class).single();
        assertThat(attemptGoogleLogin("google-" + UUID.randomUUID(), email, true, "Someone"))
                .isEqualTo("/login?error=account_exists");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM app_user").query(Integer.class).single()).isEqualTo(before);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM user_action_token").query(Integer.class).single()).isZero();
    }
}
