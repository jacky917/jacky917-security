package jacky917.security.authorizationserver.token;

import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserAuthorities;
import jacky917.security.core.TrustLevel;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Set;
import java.util.TreeSet;

/**
 * Default {@link AuthorityResolver} (D07).
 * <p>
 * 預設的 {@link AuthorityResolver}（D07）。
 * <ul>
 *   <li>First-party clients receive all of the user's roles and
 *       permissions.
 *       <br>第一方 client 取得使用者全部的角色與權限。</li>
 *   <li>Third-party clients receive no roles, and only the permissions that
 *       both the user holds and the granted scopes cover (data model
 *       §11.3).
 *       <br>第三方 client 不取得角色，權限只有「使用者擁有」且「同意的 scope
 *       涵蓋」的部分（資料模型 §11.3）。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
public class DefaultAuthorityResolver implements AuthorityResolver {

    private final UserAccountService users;
    private final JdbcClient jdbc;
    private final Clock clock;

    /**
     * Creates the resolver.
     * <p>
     * 建立 resolver。
     *
     * @param users  the user account service
     *               <br>使用者帳號服務
     * @param jdbc   the JDBC client of the authorization server database
     *               <br>Authorization Server 資料庫的 JDBC client
     * @param clock  the clock for role expiry
     *               <br>判斷角色到期所用的時鐘
     */
    public DefaultAuthorityResolver(UserAccountService users, JdbcClient jdbc, Clock clock) {
        this.users = users;
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public ResolvedAuthorities resolve(String userId, RegisteredClient client, TrustLevel trustLevel,
                                       Set<String> grantedScopes) {
        if (trustLevel == TrustLevel.FIRST_PARTY) {
            UserAuthorities authorities = users.loadAuthorities(userId);
            return new ResolvedAuthorities(authorities.roles(), authorities.permissions());
        }
        if (grantedScopes.isEmpty()) {
            return new ResolvedAuthorities(Set.of(), Set.of());
        }
        Set<String> permissions = new TreeSet<>(jdbc.sql("""
                        SELECT DISTINCT p.code
                        FROM app_scope_permission sp
                        JOIN app_permission p ON p.id = sp.permission_id
                        WHERE sp.scope_code IN (:scopes)
                          AND p.id IN (
                              SELECT rp.permission_id
                              FROM app_user_role ur
                              JOIN app_role_permission rp ON rp.role_id = ur.role_id
                              WHERE ur.user_id = :user AND (ur.expires_at IS NULL OR ur.expires_at > :now))""")
                .param("scopes", grantedScopes)
                .param("user", userId)
                .param("now", Timestamp.from(clock.instant()))
                .query(String.class).list());
        return new ResolvedAuthorities(Set.of(), Set.copyOf(permissions));
    }
}
