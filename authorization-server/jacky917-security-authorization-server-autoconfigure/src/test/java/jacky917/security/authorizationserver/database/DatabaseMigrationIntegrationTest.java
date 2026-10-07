package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.security.Principal;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 兩種資料庫各從空資料庫執行全部 migration，並以 Spring Security 官方 JDBC 類別與關鍵約束驗證結構
 * （資料模型 §13.2、詳細設計 T-DB-01、T-DB-03）。
 */
@DisplayName("資料庫 migration 整合測試（SQLite／PostgreSQL）")
class DatabaseMigrationIntegrationTest {

    static final List<String> TABLES = List.of(
            "app_user", "user_federated_identity", "user_action_token",
            "app_role", "app_permission", "app_user_role", "app_role_permission",
            "api_resource", "app_scope", "app_scope_permission",
            "oauth2_registered_client", "oauth2_authorization", "oauth2_authorization_consent", "client_profile",
            "auth_session", "session_authorization", "refresh_token_history",
            "spring_session", "spring_session_attributes",
            "signing_key", "login_audit", "admin_audit_log", "shedlock");

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("建立全部 23 張表與內建資料，並選擇對應的方言")
    void migrationsCreateSchemaAndSeed(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(AuthorizationServerDialect.class).vendor()).isEqualTo(vendor);
            assertThat(SchemaIntrospection.of(vendor, context.getBean(JdbcOperations.class)).tables())
                    .containsExactlyInAnyOrderElementsOf(TABLES);

            JdbcClient jdbc = context.getBean(JdbcClient.class);
            assertThat(jdbc.sql("SELECT code FROM app_role").query(String.class).list())
                    .containsExactlyInAnyOrder("AS_ADMIN", "AS_SUPPORT", "USER");
            assertThat(jdbc.sql("SELECT COUNT(*) FROM app_permission").query(Integer.class).single()).isEqualTo(8);
            assertThat(jdbc.sql("""
                    SELECT p.code FROM app_role_permission rp
                    JOIN app_role r ON r.id = rp.role_id JOIN app_permission p ON p.id = rp.permission_id
                    WHERE r.code = 'AS_SUPPORT'""").query(String.class).list())
                    .containsExactlyInAnyOrder("as:user:read", "as:session:revoke", "as:audit:read");
            assertThat(jdbc.sql("SELECT code FROM app_scope WHERE consent_required = :required")
                    .param("required", false).query(String.class).list()).containsExactly("openid");
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("官方 JdbcRegisteredClientRepository 與 JdbcOAuth2AuthorizationService 可直接使用（不需自訂 mixin）")
    void officialJdbcClassesWork(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            JdbcOperations jdbc = context.getBean(JdbcOperations.class);
            JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(jdbc);
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("web-bff")
                    .clientSecret("{noop}secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://app.example.com/login/oauth2/code/jacky917")
                    .scope("openid")
                    .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())
                    .build();
            clients.save(client);
            assertThat(clients.findByClientId("web-bff").getTokenSettings().isReuseRefreshTokens()).isFalse();

            JdbcOAuth2AuthorizationService authorizations = new JdbcOAuth2AuthorizationService(jdbc, clients);
            Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            String userId = UUID.randomUUID().toString();
            // D16：principal 一律是 UsernamePasswordAuthenticationToken + User，username = app_user.id
            var principal = UsernamePasswordAuthenticationToken.authenticated(
                    new User(userId, "", AuthorityUtils.createAuthorityList("ROLE_USER")), null,
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                    .id(UUID.randomUUID().toString())
                    .principalName(userId)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .attribute(Principal.class.getName(), principal)
                    .refreshToken(new OAuth2RefreshToken("refresh-" + vendor, now, now.plus(Duration.ofDays(14))))
                    .build();
            authorizations.save(authorization);

            OAuth2Authorization found = authorizations.findByToken("refresh-" + vendor, OAuth2TokenType.REFRESH_TOKEN);
            assertThat(found).isNotNull();
            assertThat(found.getPrincipalName()).isEqualTo(userId);
            assertThat(found.getRefreshToken().getToken().getExpiresAt()).isEqualTo(now.plus(Duration.ofDays(14)));
            UsernamePasswordAuthenticationToken restored = found.getAttribute(Principal.class.getName());
            assertThat(restored.getName()).isEqualTo(userId);
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("約束：狀態值、只能有一把 ACTIVE 金鑰、REVOKED 必須有 revoked_at、Email 不分大小寫唯一")
    void constraintsRejectInvalidRows(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            JdbcClient jdbc = context.getBean(JdbcClient.class);
            Timestamp now = Timestamp.from(Instant.now());

            assertThatThrownBy(() -> insertUser(jdbc, "a@example.com", "BANNED", now))
                    .isInstanceOf(DataIntegrityViolationException.class);
            String userId = insertUser(jdbc, "Alice@Example.com", "ACTIVE", now);
            // 兩種資料庫都必須轉換成 DuplicateKeyException（SQLite 由 SqliteExceptionTranslator 處理）
            assertThatThrownBy(() -> insertUser(jdbc, "alice@example.com", "ACTIVE", now))
                    .isInstanceOf(DuplicateKeyException.class);

            insertSigningKey(jdbc, "k1", "ACTIVE", now);
            assertThatThrownBy(() -> insertSigningKey(jdbc, "k2", "ACTIVE", now))
                    .isInstanceOf(DuplicateKeyException.class);
            insertSigningKey(jdbc, "k3", "RETIRED", now);

            assertThatThrownBy(() -> jdbc.sql("""
                    INSERT INTO auth_session (session_id, user_id, status, login_method, created_at, last_seen_at, expires_at)
                    VALUES (:id, :user, 'REVOKED', 'PASSWORD', :now, :now, :expires)""")
                    .param("id", UUID.randomUUID().toString()).param("user", userId).param("now", now)
                    .param("expires", Timestamp.from(now.toInstant().plus(Duration.ofDays(1)))).update())
                    .isInstanceOf(DataIntegrityViolationException.class);

            // 外鍵：不存在的使用者
            assertThatThrownBy(() -> jdbc.sql("""
                    INSERT INTO user_federated_identity (id, user_id, provider, provider_subject, linked_at)
                    VALUES (:id, 'no-such-user', 'google', 'x', :now)""")
                    .param("id", UUID.randomUUID().toString()).param("now", now).update())
                    .isInstanceOf(DataIntegrityViolationException.class);
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("外鍵：刪除使用者時，連帶刪除登入 Session 與外部帳號")
    void foreignKeysCascade(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            JdbcClient jdbc = context.getBean(JdbcClient.class);
            Timestamp now = Timestamp.from(Instant.now());
            String userId = insertUser(jdbc, "bob@example.com", "ACTIVE", now);
            jdbc.sql("""
                    INSERT INTO auth_session (session_id, user_id, login_method, created_at, last_seen_at, expires_at)
                    VALUES (:id, :user, 'PASSWORD', :now, :now, :expires)""")
                    .param("id", UUID.randomUUID().toString()).param("user", userId).param("now", now)
                    .param("expires", Timestamp.from(now.toInstant().plus(Duration.ofDays(1)))).update();
            jdbc.sql("""
                    INSERT INTO user_federated_identity (id, user_id, provider, provider_subject, linked_at)
                    VALUES (:id, :user, 'google', '1234567890', :now)""")
                    .param("id", UUID.randomUUID().toString()).param("user", userId).param("now", now).update();

            jdbc.sql("DELETE FROM app_user WHERE id = :id").param("id", userId).update();

            assertThat(jdbc.sql("SELECT COUNT(*) FROM auth_session").query(Integer.class).single()).isZero();
            assertThat(jdbc.sql("SELECT COUNT(*) FROM user_federated_identity").query(Integer.class).single()).isZero();
        });
    }

    private static String insertUser(JdbcClient jdbc, String email, String status, Timestamp now) {
        String id = UUID.randomUUID().toString();
        jdbc.sql("""
                INSERT INTO app_user (id, email, email_verified, status, created_at, updated_at)
                VALUES (:id, :email, :verified, :status, :now, :now)""")
                .param("id", id).param("email", email).param("verified", true).param("status", status)
                .param("now", now).update();
        return id;
    }

    private static void insertSigningKey(JdbcClient jdbc, String kid, String status, Timestamp now) {
        jdbc.sql("""
                INSERT INTO signing_key (kid, public_key, private_key_encrypted, encryption_key_id, status, created_at)
                VALUES (:kid, 'public', 'encrypted', 'v1', :status, :now)""")
                .param("kid", kid).param("status", status).param("now", now).update();
    }
}
