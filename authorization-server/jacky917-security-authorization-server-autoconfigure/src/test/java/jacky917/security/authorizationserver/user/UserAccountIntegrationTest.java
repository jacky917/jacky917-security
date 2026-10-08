package jacky917.security.authorizationserver.user;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.context.ApplicationContext;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 使用者帳號與帳號密碼登入（詳細設計 D16、D21、T-LOGIN-01／02／04 的驗證部分）。
 * 以 Spring Security 的 {@code DaoAuthenticationProvider} 實際驗證，與登入頁使用的元件相同。
 */
@DisplayName("使用者與帳號密碼驗證整合測試（SQLite／PostgreSQL）")
class UserAccountIntegrationTest {

    private static final String PASSWORD = "correct horse battery";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("以帳號或已驗證的 Email 登入（不分大小寫），Authentication 的 name 為使用者 ID（D16）")
    void loginWithUsernameOrVerifiedEmail(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            UserAccount alice = users(context).createUser(new NewUser("alice", "Alice@Example.com", true, PASSWORD,
                    "Alice", Set.of("AS_SUPPORT")));
            assertThat(alice.id()).hasSize(36).matches("[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");

            for (String login : new String[]{"alice", "ALICE", "alice@example.com", " Alice@Example.COM "}) {
                Authentication result = authenticate(context, login, PASSWORD);
                assertThat(result.getName()).as(login).isEqualTo(alice.id());
            }
            // FACTOR_PASSWORD 由 Spring Security 7 自動加入（多因素驗證用），不是本專案的權限
            assertThat(authorities(authenticate(context, "alice", PASSWORD))).containsExactlyInAnyOrder(
                    "ROLE_USER", "ROLE_AS_SUPPORT", "PERM_as:user:read", "PERM_as:session:revoke", "PERM_as:audit:read",
                    "FACTOR_PASSWORD");
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("帳號不存在、密碼錯誤、未驗證的 Email、沒有密碼、已刪除：都是相同的 BadCredentialsException（防止帳號列舉）")
    void failuresLookTheSame(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            UserAccountService users = users(context);
            users.createUser(new NewUser("bob", "bob@example.com", false, PASSWORD, null, Set.of()));
            users.createUser(new NewUser(null, "fed@example.com", true, null, null, Set.of()));
            UserAccount deleted = users.createUser(new NewUser("deleted", null, false, PASSWORD, null, Set.of()));
            setColumn(context, deleted.id(), "status", "DELETED");

            // Spring Security 的訊息會依 JVM 語系翻譯，因此比較「所有失敗的例外與訊息都相同」，而不是比對固定字串
            Set<String> messages = new java.util.HashSet<>();
            for (String[] attempt : new String[][]{{"nobody", PASSWORD}, {"bob", "wrong password!!"},
                    {"bob@example.com", PASSWORD}, {"fed@example.com", "anything at all"}, {"deleted", PASSWORD}}) {
                Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(
                        () -> authenticate(context, attempt[0], attempt[1]));
                assertThat(thrown).as(attempt[0]).isExactlyInstanceOf(BadCredentialsException.class);
                messages.add(thrown.getMessage());
            }
            assertThat(messages).hasSize(1);
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("停用、管理員鎖定、暫時鎖定（locked_until）的帳號無法登入；鎖定到期後恢復")
    void disabledAndLockedAccounts(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            UserAccountService users = users(context);
            UserAccount disabled = users.createUser(new NewUser("disabled", null, false, PASSWORD, null, Set.of()));
            setColumn(context, disabled.id(), "status", "DISABLED");
            UserAccount locked = users.createUser(new NewUser("locked", null, false, PASSWORD, null, Set.of()));
            setColumn(context, locked.id(), "status", "LOCKED");
            UserAccount temporary = users.createUser(new NewUser("temporary", null, false, PASSWORD, null, Set.of()));
            setLockedUntil(context, temporary.id(), Instant.now().plus(Duration.ofMinutes(15)));

            assertThatThrownBy(() -> authenticate(context, "disabled", PASSWORD)).isInstanceOf(DisabledException.class);
            assertThatThrownBy(() -> authenticate(context, "locked", PASSWORD)).isInstanceOf(LockedException.class);
            assertThatThrownBy(() -> authenticate(context, "temporary", PASSWORD)).isInstanceOf(LockedException.class);

            setLockedUntil(context, temporary.id(), Instant.now().minus(Duration.ofMinutes(1)));
            assertThat(authenticate(context, "temporary", PASSWORD).getName()).isEqualTo(temporary.id());
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("過期的角色不計入；帳號與 Email 不分大小寫唯一；不存在的角色被拒絕")
    void authoritiesAndUniqueness(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            UserAccountService users = users(context);
            UserAccount carol = users.createUser(new NewUser("carol", "carol@example.com", true, PASSWORD, null,
                    Set.of("AS_ADMIN")));
            context.getBean(JdbcClient.class).sql("UPDATE app_user_role SET expires_at = :past WHERE user_id = :id "
                            + "AND role_id = (SELECT id FROM app_role WHERE code = 'AS_ADMIN')")
                    .param("past", Timestamp.from(Instant.now().minusSeconds(60))).param("id", carol.id()).update();
            assertThat(users.loadAuthorities(carol.id())).isEqualTo(new UserAuthorities(Set.of("USER"), Set.of()));

            assertThatThrownBy(() -> users.createUser(new NewUser("CAROL", null, false, PASSWORD, null, Set.of())))
                    .isInstanceOf(DuplicateKeyException.class);
            assertThatThrownBy(() -> users.createUser(new NewUser("carol2", "CAROL@example.com", true, PASSWORD, null,
                    Set.of()))).isInstanceOf(DuplicateKeyException.class);
            assertThatThrownBy(() -> users.createUser(new NewUser("dave", null, false, PASSWORD, null, Set.of("NOPE"))))
                    .hasMessageContaining("Role NOPE does not exist");
            assertThat(users.findByLogin("dave")).as("建立失敗時整筆交易回滾").isEmpty();
        });
    }

    @Test
    @DisplayName("帳號規則與密碼政策（至少 12 字元）")
    void usernameAndPasswordRules() {
        TestDatabases.runner(TestDatabases.SQLITE).run(context -> {
            UserAccountService users = users(context);
            assertThatThrownBy(() -> users.createUser(new NewUser("a@b", null, false, PASSWORD, null, Set.of())))
                    .hasMessageContaining("no '@'");
            assertThatThrownBy(() -> users.createUser(new NewUser("ab", null, false, PASSWORD, null, Set.of())))
                    .hasMessageContaining("3-64 characters");
            assertThatThrownBy(() -> users.createUser(new NewUser("erin", null, false, "short pass", null, Set.of())))
                    .hasMessageContaining("at least 12 characters");
            assertThatThrownBy(() -> users.createUser(new NewUser("erin", null, false, "x".repeat(129), null, Set.of())))
                    .hasMessageContaining("at most 128 characters");
        });
    }

    @Test
    @DisplayName("密碼雜湊以 {bcrypt} 儲存；強度調高後登入時自動重新雜湊（D21）")
    void passwordIsRehashedAfterStrengthIncrease() {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        String[] hash = new String[2];
        TestDatabases.runner(TestDatabases.SQLITE, url)
                .withPropertyValues("jacky917.security.authorization-server.password.bcrypt-strength=10")
                .run(context -> {
                    UserAccount frank = users(context).createUser(new NewUser("frank", null, false, PASSWORD, null, Set.of()));
                    hash[0] = frank.id();
                    hash[1] = frank.passwordHash();
                    assertThat(hash[1]).startsWith("{bcrypt}$2a$10$");
                });
        TestDatabases.runner(TestDatabases.SQLITE, url).run(context -> {
            authenticate(context, "frank", PASSWORD);
            String upgraded = users(context).findById(hash[0]).orElseThrow().passwordHash();
            assertThat(upgraded).startsWith("{bcrypt}$2a$12$");
            assertThat(users(context).findById(hash[0]).orElseThrow().passwordChangedAt())
                    .as("重新雜湊不算變更密碼，不會撤銷其他 Session").isNotNull();
        });
    }

    @Test
    @DisplayName("第一位管理員只建立一次；重新啟動不會重複建立")
    void bootstrapAdminIsCreatedOnce() {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        String[] properties = {"jacky917.security.authorization-server.bootstrap-admin.username=admin",
                "jacky917.security.authorization-server.bootstrap-admin.password=" + PASSWORD,
                "jacky917.security.authorization-server.bootstrap-admin.email=admin@example.com"};
        TestDatabases.runner(TestDatabases.SQLITE, url).withPropertyValues(properties).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(authorities(authenticate(context, "admin@example.com", PASSWORD))).contains("ROLE_AS_ADMIN");
        });
        TestDatabases.runner(TestDatabases.SQLITE, url).withPropertyValues(properties).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JdbcClient.class).sql("SELECT COUNT(*) FROM app_user").query(Integer.class)
                    .single()).isEqualTo(1);
        });
    }

    private static UserAccountService users(ApplicationContext context) {
        return context.getBean(UserAccountService.class);
    }

    private static Authentication authenticate(ApplicationContext context, String login, String password) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(context.getBean(UserDetailsService.class));
        provider.setPasswordEncoder(context.getBean(PasswordEncoder.class));
        provider.setUserDetailsPasswordService((UserDetailsPasswordService) context.getBean(UserDetailsService.class));
        return provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(login, password));
    }

    private static Set<String> authorities(Authentication authentication) {
        return Set.copyOf(authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    private static void setColumn(ApplicationContext context, String userId, String column, String value) {
        context.getBean(JdbcClient.class).sql("UPDATE app_user SET " + column + " = :value WHERE id = :id")
                .param("value", value).param("id", userId).update();
    }

    private static void setLockedUntil(ApplicationContext context, String userId, Instant until) {
        context.getBean(JdbcClient.class).sql("UPDATE app_user SET locked_until = :until WHERE id = :id")
                .param("until", Timestamp.from(until)).param("id", userId).update();
    }
}
