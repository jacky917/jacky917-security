package jacky917.security.authorizationserver.token;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Set;

/**
 * Decides the audience ({@code aud}) of an access token. Replace this bean
 * to give each API its own audience.
 * <p>
 * 決定 Access Token 的 audience（{@code aud}）。替換此 bean 即可讓每個 API
 * 使用自己的 audience。
 *
 * @author Jacky
 * @since 2.1.0
 */
@FunctionalInterface
public interface AudienceResolver {

    /**
     * Returns the audience of an access token.
     * <p>
     * 回傳 Access Token 的 audience。
     *
     * @param client         the client the token is issued to
     *                       <br>取得 token 的 client
     * @param grantedScopes  the scopes in the token
     *                       <br>token 中的 scope
     * @return the audience values; must not be empty
     *         <br>audience；不可為空
     */
    List<String> resolve(RegisteredClient client, Set<String> grantedScopes);
}
