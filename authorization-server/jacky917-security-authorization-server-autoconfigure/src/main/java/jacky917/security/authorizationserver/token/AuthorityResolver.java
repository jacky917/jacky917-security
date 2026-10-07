package jacky917.security.authorizationserver.token;

import jacky917.security.core.TrustLevel;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;

/**
 * Decides which roles and permissions an access token carries (D07, D18).
 * <p>
 * 決定 Access Token 帶有哪些角色與權限（D07、D18）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@FunctionalInterface
public interface AuthorityResolver {

    /**
     * Returns the user's roles and permissions for a token, read from the
     * database each time a token is issued.
     * <p>
     * 回傳 token 中使用者的角色與權限；每次簽發 token 時都從資料庫讀取。
     *
     * @param userId         the user id
     *                       <br>使用者 ID
     * @param client         the client the token is issued to
     *                       <br>取得 token 的 client
     * @param trustLevel     the client's trust level
     *                       <br>client 的信任等級
     * @param grantedScopes  the scopes in the token
     *                       <br>token 中的 scope
     * @return the roles and permissions
     *         <br>角色與權限
     */
    ResolvedAuthorities resolve(String userId, RegisteredClient client, TrustLevel trustLevel, Set<String> grantedScopes);
}
