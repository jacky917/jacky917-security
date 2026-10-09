package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.client.ClientDetails;
import jacky917.security.authorizationserver.client.ClientProfile;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.client.ClientRegistrationSynchronizer;
import jacky917.security.authorizationserver.client.ClientStatus;
import jacky917.security.authorizationserver.client.ClientUris;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.core.TrustLevel;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.transaction.support.TransactionOperations;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Manages clients for the administration API (phase 3 and 4 design §6.4,
 * D30).
 * <p>
 * 為管理 API 管理 client（第 3、4 階段設計 §6.4、D30）。
 * <ul>
 *   <li>Clients created here are third-party clients: they always ask users
 *       to consent, must have a privacy policy, use the authorization code
 *       flow only, and can ask only for scopes defined in {@code app_scope}
 *       that do not start with {@code as:}. First-party clients belong in
 *       the configuration.
 *       <br>在此建立的 client 都是第三方 client：一律要求使用者同意、必須有
 *       隱私權政策、只使用授權碼流程，且只能要求 {@code app_scope} 中定義、
 *       不以 {@code as:} 開頭的 scope。第一方 client 應寫在設定檔中。</li>
 *   <li>Clients in the configuration can be read but not changed
 *       ({@code 409}); the configuration overwrites them at every startup.
 *       <br>設定檔中的 client 可以讀取但不能修改（{@code 409}）；設定檔在每次
 *       啟動時覆寫它們。</li>
 *   <li>A secret is returned only when it is created; only its hash is
 *       stored.
 *       <br>Secret 只在產生時回傳一次；只儲存其雜湊。</li>
 *   <li>Suspending or deleting a client deletes its authorizations, so its
 *       refresh tokens stop working at once.
 *       <br>停權或刪除 client 時刪除它的授權，Refresh Token 立即失效。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ClientAdminService {

    private static final Pattern CLIENT_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{1,99}");
    private static final int NAME_MAX_LENGTH = 128;
    private static final int URL_MAX_LENGTH = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcClient jdbc;
    private final RegisteredClientRepository clients;
    private final ClientProfileRepository profiles;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationServerProperties properties;
    private final AdminAuditService audit;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc             the JDBC client of the authorization server
     *                         database
     *                         <br>Authorization Server 資料庫的 JDBC client
     * @param clients          the registered clients, including suspended ones
     *                         <br>已註冊的 client，包含已停權的
     * @param profiles         the client profiles
     *                         <br>client 資料
     * @param passwordEncoder  hashes the secrets
     *                         <br>雜湊 secret
     * @param properties       the authorization server properties: the
     *                         clients in the configuration and the token
     *                         settings
     *                         <br>Authorization Server 設定屬性：設定檔中的
     *                         client 與 token 設定
     * @param audit            records the changes
     *                         <br>記錄變更
     * @param transactions     runs each change in one transaction
     *                         <br>每一項變更在同一個交易中執行
     * @param clock            the clock
     *                         <br>時鐘
     */
    public ClientAdminService(JdbcClient jdbc, RegisteredClientRepository clients, ClientProfileRepository profiles,
                              PasswordEncoder passwordEncoder, AuthorizationServerProperties properties,
                              AdminAuditService audit, TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.clients = clients;
        this.profiles = profiles;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Returns every client, ordered by client id.
     * <p>
     * 回傳所有 client，依 client id 排序。
     *
     * @return the clients
     *         <br>client
     */
    public List<ClientView> clients() {
        return jdbc.sql("SELECT client_id FROM oauth2_registered_client").query(String.class).list().stream()
                .sorted(Comparator.naturalOrder()).map(this::client).toList();
    }

    /**
     * Returns a client.
     * <p>
     * 回傳一個 client。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client
     *         <br>client
     * @throws AdminApiException {@code 404} if it does not exist
     *         <br>不存在時為 {@code 404}
     */
    public ClientView client(String clientId) {
        RegisteredClient client = find(clientId);
        ClientProfile profile = profiles.find(client.getId()).orElse(null);
        ClientDetails details = profiles.details(client.getId()).orElse(ClientDetails.NONE);
        return new ClientView(client.getClientId(), profile == null ? client.getClientName() : profile.displayName(),
                details.description(),
                profile == null ? TrustLevel.FIRST_PARTY.name() : profile.trustLevel().name(),
                profile == null ? ClientStatus.ACTIVE.name() : profile.status().name(),
                properties.getClients().containsKey(clientId),
                client.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).sorted()
                        .toList(),
                client.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).sorted().toList(),
                List.copyOf(client.getRedirectUris()), List.copyOf(client.getPostLogoutRedirectUris()),
                client.getScopes().stream().sorted().toList(), details.logoUrl(), details.homepageUrl(),
                details.privacyPolicyUrl(), details.termsUrl(), client.getClientIdIssuedAt());
    }

    /**
     * Creates a third-party client.
     * <p>
     * 建立第三方 client。
     *
     * @param request  the client
     *                 <br>client
     * @return the client, and its secret unless it is a public client
     *         <br>client，以及其 secret（public client 除外）
     * @throws AdminApiException {@code 400} if the request is not valid;
     *         {@code 409} if the client id is used
     *         <br>請求不正確時為 {@code 400}；client id 已被使用時為
     *         {@code 409}
     */
    public CreatedClient create(ClientRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.clientId() == null || !CLIENT_ID.matcher(request.clientId()).matches()) {
            errors.put("clientId", "must be 2-100 lower case letters, digits, '.', '_' or '-'");
        }
        checkName(request.name(), errors);
        ClientAuthenticationMethod method = authenticationMethod(request.authenticationMethod(), errors);
        ClientStatus status = initialStatus(request.status(), errors);
        ClientDetails details = details(request.description(), request.logoUrl(), request.homepageUrl(),
                request.privacyPolicyUrl(), request.termsUrl(), true, errors);
        List<String> redirectUris = redirectUris("redirectUris", request.redirectUris(), true, errors);
        List<String> postLogoutRedirectUris = redirectUris("postLogoutRedirectUris", request.postLogoutRedirectUris(),
                false, errors);
        Set<String> scopes = scopes(request.scopes(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        String clientId = request.clientId();
        if (properties.getClients().containsKey(clientId)) {
            throw AdminApiException.conflict("Client " + clientId + " is defined in the configuration");
        }
        boolean publicClient = ClientAuthenticationMethod.NONE.equals(method);
        String secret = publicClient ? null : newSecret();
        transactions.executeWithoutResult(tx -> {
            if (clients.findByClientId(clientId) != null) {
                throw AdminApiException.conflict("Client " + clientId + " already exists");
            }
            Instant now = clock.instant();
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientIdIssuedAt(now)
                    .clientName(request.name().strip())
                    .clientSecret(secret == null ? null : passwordEncoder.encode(secret))
                    .clientAuthenticationMethod(method)
                    .authorizationGrantTypes(types -> {
                        types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                        // public client 不取得 Refresh Token（與設定檔的規則相同）
                        if (!publicClient) {
                            types.add(AuthorizationGrantType.REFRESH_TOKEN);
                        }
                    })
                    .redirectUris(uris -> uris.addAll(redirectUris))
                    .postLogoutRedirectUris(uris -> uris.addAll(postLogoutRedirectUris))
                    .scopes(values -> values.addAll(scopes))
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true)
                            .build())
                    .tokenSettings(ClientRegistrationSynchronizer.tokenSettings(properties))
                    .build();
            clients.save(client);
            profiles.create(client.getId(), TrustLevel.THIRD_PARTY, request.name().strip(), details, status, now);
            audit.record("CLIENT_CREATED", AdminAuditTarget.CLIENT, clientId, null, client(clientId));
        });
        return new CreatedClient(client(clientId), secret);
    }

    /**
     * Changes the given fields of a client that is not defined in the
     * configuration; {@code null} fields stay the same, and an empty text
     * clears the description or an optional address. The trust level stays
     * as it is, and the token lifetimes follow the current configuration.
     * <p>
     * 變更未定義在設定檔中之 client 的指定欄位；{@code null} 的欄位維持不變，空
     * 字串會清除說明或選填的網址。信任等級維持不變，token 有效期跟隨目前的
     * 設定。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @param request   the fields to change
     *                  <br>要變更的欄位
     * @return the client
     *         <br>client
     * @throws AdminApiException {@code 400} if a field is not valid;
     *         {@code 404} if the client does not exist; {@code 409} if it is
     *         defined in the configuration
     *         <br>欄位不正確時為 {@code 400}；client 不存在時為 {@code 404}；
     *         定義在設定檔中時為 {@code 409}
     */
    public ClientView update(String clientId, ClientUpdate request) {
        ClientView before = managedHere(clientId);
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.name() != null) {
            checkName(request.name(), errors);
        }
        // 從設定檔移除的舊 client 可能是第一方：保留原本的信任等級，只有第三方必須有隱私權政策
        TrustLevel trustLevel = TrustLevel.valueOf(before.trustLevel());
        ClientDetails details = details(
                merge(request.description(), before.description()), merge(request.logoUrl(), before.logoUrl()),
                merge(request.homepageUrl(), before.homepageUrl()),
                merge(request.privacyPolicyUrl(), before.privacyPolicyUrl()),
                merge(request.termsUrl(), before.termsUrl()), trustLevel == TrustLevel.THIRD_PARTY, errors);
        List<String> redirectUris = request.redirectUris() == null ? null
                : redirectUris("redirectUris", request.redirectUris(), true, errors);
        List<String> postLogoutRedirectUris = request.postLogoutRedirectUris() == null ? null
                : redirectUris("postLogoutRedirectUris", request.postLogoutRedirectUris(), false, errors);
        Set<String> scopes = request.scopes() == null ? null : scopes(request.scopes(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        String name = request.name() == null ? before.name() : request.name().strip();
        transactions.executeWithoutResult(tx -> {
            save(clientId, builder -> {
                builder.clientName(name);
                if (redirectUris != null) {
                    builder.redirectUris(uris -> {
                        uris.clear();
                        uris.addAll(redirectUris);
                    });
                }
                if (postLogoutRedirectUris != null) {
                    builder.postLogoutRedirectUris(uris -> {
                        uris.clear();
                        uris.addAll(postLogoutRedirectUris);
                    });
                }
                if (scopes != null) {
                    builder.scopes(values -> {
                        values.clear();
                        values.addAll(scopes);
                    });
                }
                // token 有效期跟隨目前的設定
                builder.tokenSettings(ClientRegistrationSynchronizer.tokenSettings(properties));
            });
            profiles.createOrUpdate(find(clientId).getId(), trustLevel, name, details, clock.instant());
            audit.record("CLIENT_UPDATED", AdminAuditTarget.CLIENT, clientId, before, client(clientId));
        });
        return client(clientId);
    }

    /**
     * Replaces the secret of a confidential client; the old one stops
     * working at once.
     * <p>
     * 取代 confidential client 的 secret；舊的立即失效。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client and its new secret
     *         <br>client 與新的 secret
     * @throws AdminApiException {@code 404} if the client does not exist;
     *         {@code 409} if it is defined in the configuration or is a
     *         public client
     *         <br>client 不存在時為 {@code 404}；定義在設定檔中或為 public
     *         client 時為 {@code 409}
     */
    public CreatedClient regenerateSecret(String clientId) {
        ClientView before = managedHere(clientId);
        if (before.authenticationMethods().contains(ClientAuthenticationMethod.NONE.getValue())) {
            throw AdminApiException.conflict("Client " + clientId + " is a public client and has no secret");
        }
        String secret = newSecret();
        transactions.executeWithoutResult(tx -> {
            save(clientId, builder -> builder.clientSecret(passwordEncoder.encode(secret)));
            audit.record("CLIENT_SECRET_CHANGED", AdminAuditTarget.CLIENT, clientId, null, null);
        });
        return new CreatedClient(client(clientId), secret);
    }

    /**
     * Changes the status of a client that is not defined in the
     * configuration: approving a
     * client under review, suspending a client, or activating a suspended
     * one. Suspending deletes the client's authorizations.
     * <p>
     * 變更未定義在設定檔中之 client 的狀態：核准審核中的 client、停權，或重新
     * 啟用已停權的 client。停權時刪除該 client 的授權。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @param target    the new status
     *                  <br>新的狀態
     * @return the client
     *         <br>client
     * @throws AdminApiException {@code 404} if the client does not exist;
     *         {@code 409} if it is defined in the configuration or the
     *         change is not allowed from its current status
     *         <br>client 不存在時為 {@code 404}；定義在設定檔中，或目前狀態不能
     *         如此變更時為 {@code 409}
     */
    public ClientView changeStatus(String clientId, StatusChange target) {
        ClientView before = managedHere(clientId);
        ClientStatus current = ClientStatus.valueOf(before.status());
        ClientStatus next = switch (target) {
            case APPROVE -> requireStatus(clientId, current, ClientStatus.PENDING_REVIEW, ClientStatus.ACTIVE);
            case ACTIVATE -> requireStatus(clientId, current, ClientStatus.SUSPENDED, ClientStatus.ACTIVE);
            case SUSPEND -> {
                if (current == ClientStatus.SUSPENDED) {
                    throw AdminApiException.conflict("Client " + clientId + " is already suspended");
                }
                yield ClientStatus.SUSPENDED;
            }
        };
        transactions.executeWithoutResult(tx -> {
            String registeredClientId = find(clientId).getId();
            profiles.updateStatus(registeredClientId, next, clock.instant());
            if (next == ClientStatus.SUSPENDED) {
                deleteAuthorizations(registeredClientId);
            }
            audit.record(target.auditAction, AdminAuditTarget.CLIENT, clientId, before, client(clientId));
        });
        return client(clientId);
    }

    /**
     * Deletes a client that is not defined in the configuration, with its
     * authorizations and consents.
     * <p>
     * 刪除未定義在設定檔中的 client，以及它的授權與同意紀錄。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @throws AdminApiException {@code 404} if the client does not exist;
     *         {@code 409} if it is defined in the configuration
     *         <br>client 不存在時為 {@code 404}；定義在設定檔中時為
     *         {@code 409}
     */
    public void delete(String clientId) {
        ClientView before = managedHere(clientId);
        transactions.executeWithoutResult(tx -> {
            String registeredClientId = find(clientId).getId();
            deleteAuthorizations(registeredClientId);
            jdbc.sql("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = :id")
                    .param("id", registeredClientId).update();
            // client_profile 由外鍵 ON DELETE CASCADE 一併刪除
            jdbc.sql("DELETE FROM oauth2_registered_client WHERE id = :id").param("id", registeredClientId).update();
            audit.record("CLIENT_DELETED", AdminAuditTarget.CLIENT, clientId, before, null);
        });
    }

    private void deleteAuthorizations(String registeredClientId) {
        // session_authorization 由外鍵 ON DELETE CASCADE 一併刪除
        jdbc.sql("DELETE FROM oauth2_authorization WHERE registered_client_id = :id").param("id", registeredClientId)
                .update();
    }

    private void save(String clientId, Consumer<RegisteredClient.Builder> change) {
        RegisteredClient.Builder builder = RegisteredClient.from(find(clientId));
        change.accept(builder);
        clients.save(builder.build());
    }

    private RegisteredClient find(String clientId) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) {
            throw AdminApiException.notFound("Client " + clientId);
        }
        return client;
    }

    private ClientView managedHere(String clientId) {
        ClientView client = client(clientId);
        if (client.configured()) {
            throw AdminApiException.conflict("Client " + clientId + " is defined in the configuration; change it "
                    + "there");
        }
        return client;
    }

    private static ClientStatus requireStatus(String clientId, ClientStatus current, ClientStatus required,
                                              ClientStatus next) {
        if (current != required) {
            throw AdminApiException.conflict("Client " + clientId + " is " + current + ", not " + required);
        }
        return next;
    }

    private static ClientAuthenticationMethod authenticationMethod(@Nullable String value, Map<String, String> errors) {
        if (value == null || ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(value)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(value)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }
        if (ClientAuthenticationMethod.NONE.getValue().equals(value)) {
            return ClientAuthenticationMethod.NONE;
        }
        errors.put("authenticationMethod", "must be client_secret_basic, client_secret_post or none");
        return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    }

    private static ClientStatus initialStatus(@Nullable String value, Map<String, String> errors) {
        if (value == null || ClientStatus.ACTIVE.name().equals(value)) {
            return ClientStatus.ACTIVE;
        }
        if (ClientStatus.PENDING_REVIEW.name().equals(value)) {
            return ClientStatus.PENDING_REVIEW;
        }
        errors.put("status", "must be ACTIVE or PENDING_REVIEW");
        return ClientStatus.ACTIVE;
    }

    private static ClientDetails details(@Nullable String description, @Nullable String logoUrl,
                                         @Nullable String homepageUrl, @Nullable String privacyPolicyUrl,
                                         @Nullable String termsUrl, boolean thirdParty, Map<String, String> errors) {
        if (thirdParty && (privacyPolicyUrl == null || privacyPolicyUrl.isBlank())) {
            errors.put("privacyPolicyUrl", "required for a third-party client");
        }
        return new ClientDetails(blankToNull(description), url("logoUrl", logoUrl, errors),
                url("homepageUrl", homepageUrl, errors), url("privacyPolicyUrl", privacyPolicyUrl, errors),
                url("termsUrl", termsUrl, errors));
    }

    private static @Nullable String url(String field, @Nullable String value, Map<String, String> errors) {
        String url = blankToNull(value);
        if (url != null && (url.length() > URL_MAX_LENGTH || !ClientUris.isWebUrl(url))) {
            errors.put(field, "must be an absolute https URL of at most " + URL_MAX_LENGTH + " characters");
        }
        return url;
    }

    private static List<String> redirectUris(String field, @Nullable List<String> values, boolean required,
                                             Map<String, String> errors) {
        List<String> uris = values == null ? List.of() : new ArrayList<>(new LinkedHashSet<>(values));
        if (required && uris.isEmpty()) {
            errors.put(field, "at least one is required");
        }
        uris.stream().filter(uri -> uri == null || !ClientUris.isAllowedRedirect(uri)).findFirst().ifPresent(uri ->
                errors.put(field, uri + " must be an absolute https URL without a fragment (http only for "
                        + "localhost; native apps may use a reverse-domain scheme such as com.example.app:/callback)"));
        return uris;
    }

    private Set<String> scopes(@Nullable List<String> values, Map<String, String> errors) {
        Set<String> scopes = values == null ? new LinkedHashSet<>() : new LinkedHashSet<>(values);
        for (String scope : scopes) {
            if (scope == null || scope.startsWith(AdminJwtAuthenticationConverter.ADMIN_PERMISSION_PREFIX)) {
                errors.put("scopes", "a third-party client cannot ask for scopes starting with as:");
                return scopes;
            }
            boolean defined = jdbc.sql("SELECT COUNT(*) FROM app_scope WHERE code = :code").param("code", scope)
                    .query(Integer.class).single() > 0;
            if (!defined) {
                errors.put("scopes", "scope " + scope + " is not defined; create it with POST /admin/api/scopes");
                return scopes;
            }
        }
        return scopes;
    }

    private static void checkName(@Nullable String name, Map<String, String> errors) {
        if (name == null || name.isBlank() || name.strip().length() > NAME_MAX_LENGTH) {
            errors.put("name", "required, at most " + NAME_MAX_LENGTH + " characters");
        }
    }

    private static @Nullable String merge(@Nullable String value, @Nullable String current) {
        return value == null ? current : value;
    }

    private static @Nullable String blankToNull(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    private static String newSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * A status change.
     * <p>
     * 狀態變更。
     */
    public enum StatusChange {

        /**
         * From {@code PENDING_REVIEW} to {@code ACTIVE}.
         * <p>
         * 從 {@code PENDING_REVIEW} 變為 {@code ACTIVE}。
         */
        APPROVE("CLIENT_APPROVED"),

        /**
         * From {@code PENDING_REVIEW} or {@code ACTIVE} to
         * {@code SUSPENDED}.
         * <p>
         * 從 {@code PENDING_REVIEW} 或 {@code ACTIVE} 變為 {@code SUSPENDED}。
         */
        SUSPEND("CLIENT_SUSPENDED"),

        /**
         * From {@code SUSPENDED} to {@code ACTIVE}.
         * <p>
         * 從 {@code SUSPENDED} 變為 {@code ACTIVE}。
         */
        ACTIVATE("CLIENT_ACTIVATED");

        private final String auditAction;

        StatusChange(String auditAction) {
            this.auditAction = auditAction;
        }
    }

    /**
     * A client.
     * <p>
     * Client。
     *
     * @param clientId                the client id
     *                                <br>client id
     * @param name                    the name shown to users
     *                                <br>顯示給使用者的名稱
     * @param description             the description, or {@code null}
     *                                <br>說明，或 {@code null}
     * @param trustLevel              {@code FIRST_PARTY} or {@code THIRD_PARTY}
     *                                <br>{@code FIRST_PARTY} 或
     *                                {@code THIRD_PARTY}
     * @param status                  {@code PENDING_REVIEW}, {@code ACTIVE} or
     *                                {@code SUSPENDED}
     *                                <br>{@code PENDING_REVIEW}、{@code ACTIVE}
     *                                或
     *                                {@code SUSPENDED}
     * @param configured              whether it is defined in the
     *                                configuration and therefore read-only
     *                                <br>是否定義在設定檔中（因此唯讀）
     * @param authenticationMethods   how it authenticates at the token
     *                                endpoint
     *                                <br>在 token 端點的驗證方式
     * @param grantTypes              the grant types
     *                                <br>grant type
     * @param redirectUris            the redirect URIs
     *                                <br>redirect URI
     * @param postLogoutRedirectUris  the addresses allowed after logging out
     *                                <br>登出後允許導向的網址
     * @param scopes                  the scopes it may ask for
     *                                <br>可以要求的 scope
     * @param logoUrl                 the logo, or {@code null}
     *                                <br>Logo，或 {@code null}
     * @param homepageUrl             the home page, or {@code null}
     *                                <br>首頁，或 {@code null}
     * @param privacyPolicyUrl        the privacy policy, or {@code null}
     *                                <br>隱私權政策，或 {@code null}
     * @param termsUrl                the terms of service, or {@code null}
     *                                <br>服務條款，或 {@code null}
     * @param createdAt               when it was created, or {@code null}
     *                                <br>建立時間，或 {@code null}
     */
    public record ClientView(String clientId, String name, @Nullable String description, String trustLevel,
                             String status, boolean configured, List<String> authenticationMethods,
                             List<String> grantTypes, List<String> redirectUris, List<String> postLogoutRedirectUris,
                             List<String> scopes, @Nullable String logoUrl, @Nullable String homepageUrl,
                             @Nullable String privacyPolicyUrl, @Nullable String termsUrl,
                             @Nullable Instant createdAt) {
    }

    /**
     * A client that was just created or got a new secret.
     * <p>
     * 剛建立或剛取得新 secret 的 client。
     *
     * @param client        the client
     *                      <br>client
     * @param clientSecret  the secret, shown only now; {@code null} for a
     *                      public client
     *                      <br>secret，只在此時顯示；public client 為
     *                      {@code null}
     */
    public record CreatedClient(ClientView client, @Nullable String clientSecret) {
    }

    /**
     * A third-party client to create.
     * <p>
     * 要建立的第三方 client。
     *
     * @param clientId                the client id
     *                                <br>client id
     * @param name                    the name shown to users
     *                                <br>顯示給使用者的名稱
     * @param description             the description, or {@code null}
     *                                <br>說明，或 {@code null}
     * @param authenticationMethod    {@code client_secret_basic} (default),
     *                                {@code client_secret_post}, or
     *                                {@code none} for a public client
     *                                <br>{@code client_secret_basic}（預設）、
     *                                {@code client_secret_post}，或 public
     *                                client 的 {@code none}
     * @param redirectUris            the redirect URIs; at least one
     *                                <br>redirect URI，至少一個
     * @param postLogoutRedirectUris  the addresses allowed after logging out,
     *                                or {@code null}
     *                                <br>登出後允許導向的網址，或 {@code null}
     * @param scopes                  the scopes it may ask for
     *                                <br>可以要求的 scope
     * @param logoUrl                 the logo, or {@code null}
     *                                <br>Logo，或 {@code null}
     * @param homepageUrl             the home page, or {@code null}
     *                                <br>首頁，或 {@code null}
     * @param privacyPolicyUrl        the privacy policy; required
     *                                <br>隱私權政策，必填
     * @param termsUrl                the terms of service, or {@code null}
     *                                <br>服務條款，或 {@code null}
     * @param status                  {@code ACTIVE} (default) or
     *                                {@code PENDING_REVIEW}
     *                                <br>{@code ACTIVE}（預設）或
     *                                {@code PENDING_REVIEW}
     */
    public record ClientRequest(@Nullable String clientId, @Nullable String name, @Nullable String description,
                                @Nullable String authenticationMethod, @Nullable List<String> redirectUris,
                                @Nullable List<String> postLogoutRedirectUris, @Nullable List<String> scopes,
                                @Nullable String logoUrl, @Nullable String homepageUrl,
                                @Nullable String privacyPolicyUrl, @Nullable String termsUrl,
                                @Nullable String status) {
    }

    /**
     * The fields of a client to change; {@code null} keeps a field.
     * <p>
     * 要變更的 client 欄位；{@code null} 表示維持不變。
     *
     * @param name                    the name shown to users
     *                                <br>顯示給使用者的名稱
     * @param description             the description; empty to clear it
     *                                <br>說明；空字串表示清除
     * @param redirectUris            the redirect URIs; at least one
     *                                <br>redirect URI，至少一個
     * @param postLogoutRedirectUris  the addresses allowed after logging out
     *                                <br>登出後允許導向的網址
     * @param scopes                  the scopes it may ask for
     *                                <br>可以要求的 scope
     * @param logoUrl                 the logo; empty to clear it
     *                                <br>Logo；空字串表示清除
     * @param homepageUrl             the home page; empty to clear it
     *                                <br>首頁；空字串表示清除
     * @param privacyPolicyUrl        the privacy policy; cannot be cleared
     *                                <br>隱私權政策，不能清除
     * @param termsUrl                the terms of service; empty to clear it
     *                                <br>服務條款；空字串表示清除
     */
    public record ClientUpdate(@Nullable String name, @Nullable String description,
                               @Nullable List<String> redirectUris, @Nullable List<String> postLogoutRedirectUris,
                               @Nullable List<String> scopes, @Nullable String logoUrl, @Nullable String homepageUrl,
                               @Nullable String privacyPolicyUrl, @Nullable String termsUrl) {
    }
}
