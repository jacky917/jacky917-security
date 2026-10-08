package jacky917.security.authorizationserver.client;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Hides clients whose {@code client_profile} is not {@code ACTIVE}, so a
 * suspended client fails authentication with {@code invalid_client}.
 * <p>
 * 隱藏 {@code client_profile} 不是 {@code ACTIVE} 的 client，讓停權的 client
 * 驗證失敗並得到 {@code invalid_client}。
 * <p>
 * A client without a profile is treated as active, so clients registered
 * directly through Spring Security keep working.
 * <p>
 * 沒有 client 資料的 client 視為啟用中，直接透過 Spring Security 註冊的 client
 * 仍可正常運作。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ActiveClientRegisteredClientRepository implements RegisteredClientRepository {

    private final RegisteredClientRepository delegate;
    private final ClientProfileRepository profiles;

    /**
     * Wraps the given repository.
     * <p>
     * 包裝指定的 repository。
     *
     * @param delegate  the repository that stores the clients
     *                  <br>實際儲存 client 的 repository
     * @param profiles  the client profiles
     *                  <br>client 資料
     */
    public ActiveClientRegisteredClientRepository(RegisteredClientRepository delegate, ClientProfileRepository profiles) {
        this.delegate = delegate;
        this.profiles = profiles;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        delegate.save(registeredClient);
    }

    @Override
    public @Nullable RegisteredClient findById(String id) {
        return activeOnly(delegate.findById(id));
    }

    @Override
    public @Nullable RegisteredClient findByClientId(String clientId) {
        return activeOnly(delegate.findByClientId(clientId));
    }

    private @Nullable RegisteredClient activeOnly(@Nullable RegisteredClient client) {
        if (client == null) {
            return null;
        }
        return profiles.find(client.getId())
                .filter(profile -> profile.status() != ClientStatus.ACTIVE)
                .isPresent() ? null : client;
    }
}
