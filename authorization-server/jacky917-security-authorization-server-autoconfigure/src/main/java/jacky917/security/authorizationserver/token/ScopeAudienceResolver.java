package jacky917.security.authorizationserver.token;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Set;

/**
 * Gives each access token the API resources of its scopes as audience
 * ({@code token.audience-strategy: per-scope}, D07-C): the distinct
 * {@code app_scope.api_resource_code} values of the granted scopes, in
 * code order. A token none of whose scopes belongs to an API resource, for
 * example one with only {@code openid}, gets {@code token.audience}.
 * <p>
 * 以 scope 所屬的 API resource 作為 Access Token 的 audience
 * （{@code token.audience-strategy: per-scope}，D07-C）：授予的 scope 的
 * {@code app_scope.api_resource_code}（去除重複，依代碼排序）。沒有任何 scope
 * 屬於 API resource 的 token（例如只有 {@code openid}）使用
 * {@code token.audience}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ScopeAudienceResolver implements AudienceResolver {

    private final JdbcClient jdbc;
    private final List<String> fallback;

    /**
     * Creates the resolver.
     * <p>
     * 建立 resolver。
     *
     * @param jdbc      the JDBC client of the authorization server database
     *                  <br>Authorization Server 資料庫的 JDBC client
     * @param fallback  the audience of tokens whose scopes belong to no API
     *                  resource; must not be empty
     *                  <br>scope 都不屬於任何 API resource 的 token 所用的
     *                  audience；不可為空
     */
    public ScopeAudienceResolver(JdbcClient jdbc, List<String> fallback) {
        this.jdbc = jdbc;
        this.fallback = fallback.stream().filter(value -> value != null && !value.isBlank()).toList();
    }

    @Override
    public List<String> resolve(RegisteredClient client, Set<String> grantedScopes) {
        if (grantedScopes.isEmpty()) {
            return fallback;
        }
        List<String> resources = jdbc.sql("SELECT DISTINCT api_resource_code FROM app_scope WHERE code IN (:scopes) "
                        + "AND api_resource_code IS NOT NULL ORDER BY api_resource_code")
                .param("scopes", List.copyOf(grantedScopes)).query(String.class).list();
        return resources.isEmpty() ? fallback : resources;
    }
}
