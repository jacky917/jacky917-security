package jacky917.security.authorizationserver.token;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Set;

/**
 * Gives every access token the same configured audience
 * ({@code token.audience}, D07-B).
 * <p>
 * 所有 Access Token 使用同一組設定的 audience（{@code token.audience}，D07-B）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ConfiguredAudienceResolver implements AudienceResolver {

    private final List<String> audience;

    /**
     * Creates the resolver.
     * <p>
     * 建立 resolver。
     *
     * @param audience  the audience values
     *                  <br>audience
     */
    public ConfiguredAudienceResolver(List<String> audience) {
        this.audience = audience.stream().filter(value -> value != null && !value.isBlank()).toList();
    }

    @Override
    public List<String> resolve(RegisteredClient client, Set<String> grantedScopes) {
        return audience;
    }
}
