package jacky917.security.authorizationserver.client;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties.AuthenticationMethod;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties.Client;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties.GrantType;
import jacky917.security.core.TrustLevel;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Creates or updates the clients declared in
 * {@code jacky917.security.authorization-server.clients} at startup.
 * <p>
 * 啟動時建立或更新 {@code jacky917.security.authorization-server.clients} 中
 * 宣告的 client。
 * <p>
 * The configuration is the source of truth for these clients: redirect
 * URIs, scopes, grant types, and token settings are overwritten on every
 * startup. Every client requires PKCE and rotates refresh tokens;
 * third-party clients also require consent. A suspended client stays
 * suspended. Clients created through the administration API are not
 * touched.
 * <p>
 * 這些 client 以設定為準：redirect URI、scope、grant type 與 token 設定在每次
 * 啟動時覆寫。所有 client 一律必須使用 PKCE，並輪換 Refresh Token；第三方
 * client 另外要求同意。已停權的 client 仍維持停權。透過管理 API 建立的 client
 * 不受影響。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class ClientRegistrationSynchronizer {

    private final RegisteredClientRepository clients;
    private final ClientProfileRepository profiles;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationServerProperties properties;
    private final TransactionTemplate transactions;
    private final Clock clock;

    /**
     * Creates the synchronizer.
     * <p>
     * 建立同步器。
     *
     * @param clients          the client repository
     *                         <br>client repository
     * @param profiles         the client profiles
     *                         <br>client 資料
     * @param passwordEncoder  hashes client secrets
     *                         <br>雜湊 client secret
     * @param properties       the authorization server properties
     *                         <br>Authorization Server 設定屬性
     * @param transactions     runs each client in its own transaction
     *                         <br>每個 client 在各自的交易中處理
     * @param clock            the clock for timestamps
     *                         <br>用於時間戳記的時鐘
     */
    public ClientRegistrationSynchronizer(RegisteredClientRepository clients, ClientProfileRepository profiles,
                                          PasswordEncoder passwordEncoder, AuthorizationServerProperties properties,
                                          TransactionTemplate transactions, Clock clock) {
        this.clients = clients;
        this.profiles = profiles;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Synchronizes every configured client.
     * <p>
     * 同步所有設定的 client。
     *
     * @throws IllegalStateException if a confidential client has no secret
     *         <br>confidential client 沒有 secret 時
     */
    public void synchronize() {
        for (Map.Entry<String, Client> entry : properties.getClients().entrySet()) {
            try {
                transactions.executeWithoutResult(status -> synchronize(entry.getKey(), entry.getValue()));
            } catch (DuplicateKeyException ex) {
                // 另一個實例同時建立了同一個 client：再同步一次，這次會走更新
                transactions.executeWithoutResult(status -> synchronize(entry.getKey(), entry.getValue()));
            }
        }
    }

    private void synchronize(String clientId, Client config) {
        RegisteredClient existing = clients.findByClientId(clientId);
        Instant now = clock.instant();
        RegisteredClient.Builder builder = existing != null
                ? RegisteredClient.from(existing)
                : RegisteredClient.withId(UUID.randomUUID().toString()).clientIdIssuedAt(now);
        builder.clientId(clientId)
                .clientName(displayName(clientId, config))
                .clientAuthenticationMethods(methods -> {
                    methods.clear();
                    methods.add(authenticationMethod(config.getAuthenticationMethod()));
                })
                .authorizationGrantTypes(types -> {
                    types.clear();
                    config.getGrantTypes().forEach(type -> types.add(grantType(type)));
                })
                .redirectUris(uris -> {
                    uris.clear();
                    uris.addAll(config.getRedirectUris());
                })
                .postLogoutRedirectUris(uris -> {
                    uris.clear();
                    uris.addAll(config.getPostLogoutRedirectUris());
                })
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(config.getScopes());
                })
                .clientSecret(secret(clientId, config, existing == null ? null : existing.getClientSecret()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        // 第三方 client 一律要求同意（D30）
                        .requireAuthorizationConsent(config.getTrustLevel() == TrustLevel.THIRD_PARTY)
                        .build())
                .tokenSettings(tokenSettings(properties));
        clients.save(builder.build());
        RegisteredClient saved = clients.findByClientId(clientId);
        String registeredClientId = saved != null ? saved.getId() : builder.build().getId();
        profiles.createOrUpdate(registeredClientId, config.getTrustLevel(), displayName(clientId, config),
                new ClientDetails(blankToNull(config.getDescription()), blankToNull(config.getLogoUrl()),
                        blankToNull(config.getHomepageUrl()), blankToNull(config.getPrivacyPolicyUrl()),
                        blankToNull(config.getTermsUrl())), now);
        log.info("{} client {}", existing == null ? "Registered" : "Updated", clientId);
    }

    private @Nullable String secret(String clientId, Client config, @Nullable String stored) {
        if (config.getAuthenticationMethod() == AuthenticationMethod.NONE) {
            return null;
        }
        String configured = config.getSecret();
        if (!StringUtils.hasText(configured)) {
            if (stored == null) {
                throw new IllegalStateException("Client " + clientId + " requires a secret: set "
                        + AuthorizationServerProperties.PREFIX + ".clients." + clientId
                        + ".secret, for example to ${" + clientId.toUpperCase().replaceAll("[^A-Z0-9]", "_") + "_SECRET}");
            }
            return stored;
        }
        if (configured.startsWith("{")) {
            return configured;
        }
        // 避免每次啟動都重新雜湊：已儲存的雜湊與設定相符時沿用
        if (stored != null && passwordEncoder.matches(configured, stored)) {
            return stored;
        }
        return passwordEncoder.encode(configured);
    }

    /**
     * Returns the token settings of every client: lifetimes from
     * {@code token.*}, refresh tokens rotated on each use, and ID tokens
     * signed with {@code keys.algorithm}.
     * <p>
     * 回傳所有 client 的 token 設定：有效期取自 {@code token.*}、Refresh Token
     * 每次使用都輪換、ID Token 以 {@code keys.algorithm} 簽章。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @return the token settings
     *         <br>token 設定
     */
    public static TokenSettings tokenSettings(AuthorizationServerProperties properties) {
        AuthorizationServerProperties.Token token = properties.getToken();
        return TokenSettings.builder()
                .accessTokenTimeToLive(token.getAccessTokenTtl())
                .refreshTokenTimeToLive(token.getRefreshTokenTtl())
                .authorizationCodeTimeToLive(token.getAuthorizationCodeTtl())
                // Spring Security 預設 true（不輪換）；必須明確關閉（詳細設計 §4.1）
                .reuseRefreshTokens(false)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.from(properties.getKeys().getAlgorithm().name()))
                .build();
    }

    private static @Nullable String blankToNull(@Nullable String value) {
        return StringUtils.hasText(value) ? value.strip() : null;
    }

    private static String displayName(String clientId, Client config) {
        return StringUtils.hasText(config.getDisplayName()) ? config.getDisplayName() : clientId;
    }

    private static ClientAuthenticationMethod authenticationMethod(AuthenticationMethod method) {
        return switch (method) {
            case CLIENT_SECRET_BASIC -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case CLIENT_SECRET_POST -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case NONE -> ClientAuthenticationMethod.NONE;
        };
    }

    private static AuthorizationGrantType grantType(GrantType type) {
        return switch (type) {
            case AUTHORIZATION_CODE -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case REFRESH_TOKEN -> AuthorizationGrantType.REFRESH_TOKEN;
            case CLIENT_CREDENTIALS -> AuthorizationGrantType.CLIENT_CREDENTIALS;
        };
    }
}
