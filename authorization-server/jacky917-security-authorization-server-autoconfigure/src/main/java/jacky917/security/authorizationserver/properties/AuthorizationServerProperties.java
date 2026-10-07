package jacky917.security.authorizationserver.properties;

import jacky917.security.core.TrustLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Configuration properties for the jacky917-security authorization server,
 * bound from {@code jacky917.security.authorization-server.*}.
 * <p>
 * jacky917-security Authorization Server 的設定屬性，綁定自
 * {@code jacky917.security.authorization-server.*}。
 * <p>
 * The class validates itself when it is bound, so an invalid setting (for
 * example a missing {@code issuer}) fails the application at startup
 * instead of at the first request.
 * <p>
 * 本類別在綁定時自行驗證，設定錯誤（例如未設定 {@code issuer}）會讓應用程式
 * 在啟動時失敗，而不是等到第一個請求才發現。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Getter
@Setter
@ConfigurationProperties(prefix = AuthorizationServerProperties.PREFIX)
public class AuthorizationServerProperties implements Validator {

    /**
     * The property prefix, {@code jacky917.security.authorization-server}.
     * <p>
     * 設定屬性的前綴 {@code jacky917.security.authorization-server}。
     */
    public static final String PREFIX = "jacky917.security.authorization-server";

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");
    private static final Pattern CLIENT_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{1,99}");

    /**
     * Whether the authorization server auto-configuration is enabled.
     * <p>
     * 是否啟用 Authorization Server 的自動配置。
     */
    private boolean enabled = true;

    /**
     * Issuer identifier written to the {@code iss} claim. Resource servers
     * must use exactly the same value as their issuer URI. Must use
     * {@code https} unless the host is {@code localhost}.
     * <p>
     * 寫入 {@code iss} claim 的簽發者識別碼。Resource Server 的 issuer URI
     * 必須與此值完全相同。除了 {@code localhost} 以外必須使用 {@code https}。
     */
    private URI issuer;

    /**
     * Database settings.
     * <p>
     * 資料庫設定。
     */
    private Database database = new Database();

    /**
     * Token lifetimes and audience.
     * <p>
     * Token 有效期與 audience。
     */
    private Token token = new Token();

    /**
     * Signing key settings.
     * <p>
     * 簽章金鑰設定。
     */
    private Keys keys = new Keys();

    /**
     * Password hashing settings.
     * <p>
     * 密碼雜湊設定。
     */
    private Password password = new Password();

    /**
     * First-party clients, keyed by client id. They are created or updated
     * at startup to match this configuration; clients removed from it are
     * left in the database.
     * <p>
     * 第一方 client，以 client id 為鍵。啟動時建立或更新為與此設定一致；從
     * 設定中移除的 client 不會從資料庫刪除。
     */
    private Map<String, Client> clients = new LinkedHashMap<>();

    /**
     * The first administrator, created once when no user has the
     * {@code AS_ADMIN} role.
     * <p>
     * 第一位管理員，只在沒有任何使用者擁有 {@code AS_ADMIN} 角色時建立一次。
     */
    private BootstrapAdmin bootstrapAdmin = new BootstrapAdmin();

    /**
     * Login page appearance.
     * <p>
     * 登入頁外觀。
     */
    private Branding branding = new Branding();

    @Override
    public boolean supports(Class<?> clazz) {
        return AuthorizationServerProperties.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        AuthorizationServerProperties properties = (AuthorizationServerProperties) target;
        if (!properties.isEnabled()) {
            return;
        }
        validateIssuer(properties.getIssuer(), errors);
        properties.getToken().validate(errors);
        properties.getKeys().validate(errors);
        properties.getPassword().validate(errors);
        properties.getBootstrapAdmin().validate(errors);
        properties.getBranding().validate(errors);
        properties.getClients().forEach((clientId, client) -> client.validate(clientId, errors));
    }

    static boolean isAllowedRedirect(String uri) {
        try {
            URI parsed = URI.create(uri);
            if (!parsed.isAbsolute() || parsed.getFragment() != null) {
                return false;
            }
            String scheme = parsed.getScheme();
            // RFC 8252 §7.1：原生 App 的私有 scheme 必須是反向網域名稱（含 "."），例如 com.example.app:/callback
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return scheme.contains(".");
            }
            if (parsed.getHost() == null) {
                return false;
            }
            return "https".equals(scheme) || LOCAL_HOSTS.contains(parsed.getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static void validateIssuer(URI issuer, Errors errors) {
        if (issuer == null) {
            errors.rejectValue("issuer", "required",
                    "issuer is required, for example https://auth.example.com");
            return;
        }
        if (!issuer.isAbsolute() || issuer.getHost() == null) {
            errors.rejectValue("issuer", "invalid", "issuer must be an absolute URL");
            return;
        }
        boolean local = LOCAL_HOSTS.contains(issuer.getHost());
        if (!"https".equals(issuer.getScheme()) && !(local && "http".equals(issuer.getScheme()))) {
            errors.rejectValue("issuer", "insecure", "issuer must use https (http is allowed only for localhost)");
        }
        if (issuer.getQuery() != null || issuer.getFragment() != null) {
            errors.rejectValue("issuer", "invalid", "issuer must not contain a query or fragment");
        }
    }

    private static void rejectOutOfRange(Errors errors, String field, Duration value, Duration min, Duration max) {
        if (value == null || value.compareTo(min) < 0 || value.compareTo(max) > 0) {
            errors.rejectValue(field, "range", field + " must be between " + min + " and " + max);
        }
    }

    /**
     * Database settings, bound from {@code .database.*}.
     * <p>
     * 資料庫設定，綁定自 {@code .database.*}。
     */
    @Getter
    @Setter
    public static class Database {

        /**
         * Database dialect. {@code auto} detects it from the JDBC URL.
         * <p>
         * 資料庫方言。{@code auto} 依 JDBC URL 判斷。
         */
        private DialectType dialect = DialectType.AUTO;

        /**
         * Settings for the default SQLite database.
         * <p>
         * 預設 SQLite 資料庫的設定。
         */
        private Sqlite sqlite = new Sqlite();

        /**
         * Settings for the default SQLite database, used only when
         * {@code spring.datasource.url} is not set.
         * <p>
         * 預設 SQLite 資料庫的設定，只在未設定 {@code spring.datasource.url}
         * 時使用。
         */
        @Getter
        @Setter
        public static class Sqlite {
            /**
             * Location of the database file. The parent directory is
             * created when it does not exist.
             * <p>
             * 資料庫檔案的位置。上層資料夾不存在時會自動建立。
             */
            private Path path = Path.of("./data/jacky917-auth.db");
        }
    }

    /**
     * Signing key settings, bound from {@code .keys.*}.
     * <p>
     * 簽章金鑰設定，綁定自 {@code .keys.*}。
     */
    @Getter
    @Setter
    public static class Keys {

        /**
         * Algorithm of newly generated signing keys.
         * <p>
         * 新產生之簽章金鑰的演算法。
         */
        private SigningAlgorithm algorithm = SigningAlgorithm.RS256;

        /**
         * Master key that encrypts the private signing keys in the
         * database: 32 random bytes in Base64, for example from
         * {@code openssl rand -base64 32}. Inject it from an environment
         * variable or a secret manager; never commit it to a
         * configuration file.
         * <p>
         * 加密資料庫中簽章私鑰的主金鑰：Base64 編碼的 32 bytes 隨機值，例如
         * {@code openssl rand -base64 32} 的輸出。請從環境變數或密鑰管理服務
         * 注入，不可寫在設定檔中。
         */
        private String encryptionKey;

        /**
         * Id of the master key, stored with each encrypted key. Change it
         * when the master key changes.
         * <p>
         * 主金鑰的識別碼，與每把加密後的金鑰一起儲存。更換主金鑰時一併修改。
         */
        private String encryptionKeyId = "v1";

        /**
         * Returns the decoded master key.
         * <p>
         * 回傳解碼後的主金鑰。
         *
         * @return the 32-byte master key
         *         <br>32 bytes 的主金鑰
         */
        public byte[] encryptionKeyBytes() {
            return Base64.getDecoder().decode(encryptionKey.trim());
        }

        void validate(Errors errors) {
            if (encryptionKey == null || encryptionKey.isBlank()) {
                errors.rejectValue("keys.encryptionKey", "required",
                        "keys.encryption-key is required: 32 random bytes in Base64 (openssl rand -base64 32), "
                                + "injected from an environment variable");
            } else {
                try {
                    if (encryptionKeyBytes().length != 32) {
                        errors.rejectValue("keys.encryptionKey", "length",
                                "keys.encryption-key must decode to 32 bytes (AES-256)");
                    }
                } catch (IllegalArgumentException ex) {
                    errors.rejectValue("keys.encryptionKey", "format", "keys.encryption-key must be Base64");
                }
            }
            if (encryptionKeyId == null || encryptionKeyId.isBlank()) {
                errors.rejectValue("keys.encryptionKeyId", "required", "keys.encryption-key-id must not be blank");
            }
        }
    }

    /**
     * Password hashing settings, bound from {@code .password.*} (D21).
     * <p>
     * 密碼雜湊設定，綁定自 {@code .password.*}（D21）。
     */
    @Getter
    @Setter
    public static class Password {

        /**
         * BCrypt strength (log2 of the rounds), between 10 and 14. Also used
         * for client secrets.
         * <p>
         * BCrypt 強度（回合數的 log2），10～14。client secret 也使用此設定。
         */
        private int bcryptStrength = 12;

        /**
         * Minimum password length, between 8 and 64 characters.
         * <p>
         * 密碼最短長度，8～64 字元。
         */
        private int minLength = 12;

        void validate(Errors errors) {
            if (minLength < 8 || minLength > 64) {
                errors.rejectValue("password.minLength", "range", "password.min-length must be between 8 and 64");
            }
            if (bcryptStrength < 10 || bcryptStrength > 14) {
                errors.rejectValue("password.bcryptStrength", "range", "password.bcrypt-strength must be between 10 and 14");
            }
        }
    }

    /**
     * Login page appearance, bound from {@code .branding.*}.
     * <p>
     * 登入頁外觀，綁定自 {@code .branding.*}。
     */
    @Getter
    @Setter
    public static class Branding {

        private static final Pattern COLOR = Pattern.compile("#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?");

        /**
         * Product name shown above the form.
         * <p>
         * 顯示在表單上方的產品名稱。
         */
        private String productName = "jacky917";

        /**
         * Logo URL: an absolute {@code https} URL or a path on this server.
         * <p>
         * Logo 網址：絕對的 {@code https} 網址，或本伺服器上的路徑。
         */
        private String logoUrl;

        /**
         * Primary color as {@code #rgb} or {@code #rrggbb}.
         * <p>
         * 主色，格式為 {@code #rgb} 或 {@code #rrggbb}。
         */
        private String primaryColor = "#2563eb";

        void validate(Errors errors) {
            // 主色會寫入樣式表：只接受色碼，避免注入任意 CSS
            if (primaryColor == null || !COLOR.matcher(primaryColor).matches()) {
                errors.rejectValue("branding.primaryColor", "format", "branding.primary-color must be #rgb or #rrggbb");
            }
            if (logoUrl != null && !logoUrl.isBlank() && !logoUrl.startsWith("https://")
                    && !(logoUrl.startsWith("/") && !logoUrl.startsWith("//"))) {
                errors.rejectValue("branding.logoUrl", "format",
                        "branding.logo-url must be an https URL or a path starting with /");
            }
        }
    }

    /**
     * The first administrator, bound from {@code .bootstrap-admin.*}.
     * <p>
     * 第一位管理員，綁定自 {@code .bootstrap-admin.*}。
     */
    @Getter
    @Setter
    public static class BootstrapAdmin {

        /**
         * Login name of the first administrator. Nothing is created when
         * empty.
         * <p>
         * 第一位管理員的登入帳號。未設定時不建立。
         */
        private String username;

        /**
         * Initial password; inject it from an environment variable.
         * <p>
         * 初始密碼，請從環境變數注入。
         */
        private String password;

        /**
         * Optional verified email of the administrator.
         * <p>
         * 管理員已驗證的 Email（選填）。
         */
        private String email;

        void validate(Errors errors) {
            if (username != null && !username.isBlank() && (password == null || password.isBlank())) {
                errors.rejectValue("bootstrapAdmin.password", "required",
                        "bootstrap-admin.password is required when bootstrap-admin.username is set");
            }
        }
    }

    /**
     * A first-party client, bound from {@code .clients.<client-id>.*}.
     * <p>
     * 第一方 client，綁定自 {@code .clients.<client-id>.*}。
     * <p>
     * Every client must use PKCE, and refresh tokens are rotated on each
     * use; neither can be turned off. Token lifetimes come from
     * {@code token.*}.
     * <p>
     * 所有 client 一律必須使用 PKCE，Refresh Token 每次使用都會輪換，兩者皆
     * 無法關閉。Token 有效期取自 {@code token.*}。
     */
    @Getter
    @Setter
    public static class Client {

        /**
         * Name shown to users; defaults to the client id.
         * <p>
         * 顯示給使用者的名稱，預設為 client id。
         */
        private String displayName;

        /**
         * Trust level. Only {@code first-party} is supported until the
         * consent screen is available.
         * <p>
         * 信任等級。同意畫面完成前只支援 {@code first-party}。
         */
        private TrustLevel trustLevel = TrustLevel.FIRST_PARTY;

        /**
         * How the client authenticates at the token endpoint.
         * {@code none} declares a public client (for example a mobile
         * app), which never receives refresh tokens.
         * <p>
         * client 在 token 端點的驗證方式。{@code none} 表示 public client
         * （例如行動 App），不會取得 Refresh Token。
         */
        private AuthenticationMethod authenticationMethod = AuthenticationMethod.CLIENT_SECRET_BASIC;

        /**
         * Client secret. Use a placeholder such as
         * {@code ${WEB_BFF_SECRET}} instead of writing the value in a file.
         * It is stored as a BCrypt hash; a value starting with an encoder
         * prefix such as {@code {bcrypt}} is stored as is. Changing it
         * replaces the stored secret at the next startup.
         * <p>
         * Client secret。請以 {@code ${WEB_BFF_SECRET}} 等佔位符引用環境變數，
         * 不要把值寫在檔案中。儲存時以 BCrypt 雜湊；以 {@code {bcrypt}} 等前綴
         * 開頭的值視為已雜湊，原樣儲存。修改後於下次啟動時取代已儲存的 secret。
         */
        private String secret;

        /**
         * Allowed grant types.
         * <p>
         * 允許的 grant type。
         */
        private Set<GrantType> grantTypes = new LinkedHashSet<>(List.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));

        /**
         * Exact redirect URIs for the authorization code flow; {@code https}
         * except on {@code localhost}. Native apps may use a reverse-domain
         * scheme such as {@code com.example.app:/callback} (RFC 8252).
         * <p>
         * 授權碼流程的 redirect URI，必須完全相符；{@code localhost} 以外必須
         * 使用 {@code https}。原生 App 可使用反向網域名稱的 scheme，例如
         * {@code com.example.app:/callback}（RFC 8252）。
         */
        private List<String> redirectUris = new ArrayList<>();

        /**
         * Exact URIs allowed as {@code post_logout_redirect_uri}.
         * <p>
         * 允許作為 {@code post_logout_redirect_uri} 的網址，必須完全相符。
         */
        private List<String> postLogoutRedirectUris = new ArrayList<>();

        /**
         * Scopes the client may request.
         * <p>
         * client 可以要求的 scope。
         */
        private Set<String> scopes = new LinkedHashSet<>(List.of("openid"));

        void validate(String clientId, Errors errors) {
            String path = "clients[" + clientId + "]";
            if (!CLIENT_ID.matcher(clientId).matches()) {
                errors.rejectValue("clients", "invalid", path + ": client id must be 2-100 lowercase letters, digits, "
                        + "'.', '_' or '-'");
            }
            if (trustLevel != TrustLevel.FIRST_PARTY) {
                errors.rejectValue("clients", "unsupported", path + ": only first-party clients are supported");
            }
            if (grantTypes == null || grantTypes.isEmpty()) {
                errors.rejectValue("clients", "required", path + ": grant-types must not be empty");
                return;
            }
            boolean authorizationCode = grantTypes.contains(GrantType.AUTHORIZATION_CODE);
            boolean publicClient = authenticationMethod == AuthenticationMethod.NONE;
            if (authorizationCode && redirectUris.isEmpty()) {
                errors.rejectValue("clients", "required", path + ": authorization_code requires redirect-uris");
            }
            redirectUris.stream().filter(uri -> !isAllowedRedirect(uri)).forEach(uri -> errors.rejectValue("clients",
                    "invalid", path + ": redirect URI " + uri + " must be an absolute https URL without a fragment "
                            + "(http is allowed only for localhost; native apps may use a reverse-domain scheme such "
                            + "as com.example.app:/callback)"));
            postLogoutRedirectUris.stream().filter(uri -> !isAllowedRedirect(uri)).forEach(uri -> errors.rejectValue(
                    "clients", "invalid", path + ": post-logout redirect URI " + uri + " must be an absolute https URL"));
            if (grantTypes.contains(GrantType.REFRESH_TOKEN) && !authorizationCode) {
                errors.rejectValue("clients", "invalid", path + ": refresh_token requires authorization_code");
            }
            if (publicClient && grantTypes.contains(GrantType.CLIENT_CREDENTIALS)) {
                errors.rejectValue("clients", "invalid", path + ": a public client cannot use client_credentials");
            }
            if (publicClient && grantTypes.contains(GrantType.REFRESH_TOKEN)) {
                errors.rejectValue("clients", "invalid", path + ": a public client never receives refresh tokens; "
                        + "remove refresh_token");
            }
            if (scopes.contains("openid") && !authorizationCode) {
                errors.rejectValue("clients", "invalid", path + ": the openid scope requires authorization_code");
            }
            if (secret != null && secret.startsWith("{") && !secret.startsWith("{bcrypt}")) {
                errors.rejectValue("clients", "invalid", path + ": a pre-encoded secret must use {bcrypt}");
            }
            if (publicClient && secret != null && !secret.isBlank()) {
                errors.rejectValue("clients", "invalid", path + ": a public client must not have a secret");
            }
        }
    }

    /**
     * Client authentication methods at the token endpoint.
     * <p>
     * Token 端點的 client 驗證方式。
     */
    public enum AuthenticationMethod {
        /**
         * HTTP Basic with the client id and secret.
         * <p>
         * 以 HTTP Basic 傳送 client id 與 secret。
         */
        CLIENT_SECRET_BASIC,
        /**
         * Client id and secret in the form body.
         * <p>
         * 在表單內容中傳送 client id 與 secret。
         */
        CLIENT_SECRET_POST,
        /**
         * No authentication: a public client protected by PKCE only.
         * <p>
         * 不驗證：只以 PKCE 保護的 public client。
         */
        NONE
    }

    /**
     * Supported grant types (D15).
     * <p>
     * 支援的 grant type（D15）。
     */
    public enum GrantType {
        /**
         * Authorization code with PKCE; the only way users log in.
         * <p>
         * 授權碼搭配 PKCE，使用者登入的唯一方式。
         */
        AUTHORIZATION_CODE,
        /**
         * Refresh token, for confidential clients only.
         * <p>
         * Refresh Token，只給 confidential client。
         */
        REFRESH_TOKEN,
        /**
         * Client credentials, for service-to-service calls.
         * <p>
         * Client credentials，用於服務對服務呼叫。
         */
        CLIENT_CREDENTIALS
    }

    /**
     * Supported signing algorithms.
     * <p>
     * 支援的簽章演算法。
     */
    public enum SigningAlgorithm {
        /**
         * RSA with SHA-256, 3072-bit keys.
         * <p>
         * RSA 搭配 SHA-256，金鑰長度 3072 位元。
         */
        RS256,
        /**
         * ECDSA with P-256 and SHA-256.
         * <p>
         * ECDSA 搭配 P-256 與 SHA-256。
         */
        ES256
    }

    /**
     * Supported database dialects.
     * <p>
     * 支援的資料庫方言。
     */
    public enum DialectType {
        /**
         * Detect the dialect from the JDBC URL.
         * <p>
         * 依 JDBC URL 判斷。
         */
        AUTO,
        /**
         * PostgreSQL 16 or later.
         * <p>
         * PostgreSQL 16 以上。
         */
        POSTGRESQL,
        /**
         * SQLite (single instance only).
         * <p>
         * SQLite（只能單一實例）。
         */
        SQLITE
    }

    /**
     * Token settings, bound from {@code .token.*}. The lifetimes are the
     * defaults for new clients; a client can override them in its own
     * token settings.
     * <p>
     * Token 設定，綁定自 {@code .token.*}。有效期為新 client 的預設值，個別
     * client 可在自己的 token settings 中覆寫。
     */
    @Getter
    @Setter
    public static class Token {

        /**
         * Access token lifetime, between 1 minute and 1 hour.
         * <p>
         * Access Token 有效期，1 分鐘～1 小時。
         */
        private Duration accessTokenTtl = Duration.ofMinutes(10);

        /**
         * Refresh token lifetime, between 1 hour and 90 days. Each refresh
         * issues a new refresh token with a new lifetime.
         * <p>
         * Refresh Token 有效期，1 小時～90 天。每次刷新都會換發新的 Refresh
         * Token 並重新計算有效期。
         */
        private Duration refreshTokenTtl = Duration.ofDays(14);

        /**
         * Authorization code lifetime, between 30 seconds and 5 minutes.
         * <p>
         * 授權碼有效期，30 秒～5 分鐘。
         */
        private Duration authorizationCodeTtl = Duration.ofMinutes(1);

        /**
         * Absolute lifetime of a login session; at least the refresh token
         * lifetime.
         * <p>
         * 登入 Session 的絕對有效期，不得短於 Refresh Token 有效期。
         */
        private Duration sessionMaxAge = Duration.ofDays(90);

        /**
         * Audience ({@code aud}) of access tokens.
         * <p>
         * Access Token 的 audience（{@code aud}）。
         */
        private List<String> audience = new ArrayList<>(List.of("jacky917-api"));

        void validate(Errors errors) {
            rejectOutOfRange(errors, "token.accessTokenTtl", accessTokenTtl, Duration.ofMinutes(1), Duration.ofHours(1));
            rejectOutOfRange(errors, "token.refreshTokenTtl", refreshTokenTtl, Duration.ofHours(1), Duration.ofDays(90));
            rejectOutOfRange(errors, "token.authorizationCodeTtl", authorizationCodeTtl,
                    Duration.ofSeconds(30), Duration.ofMinutes(5));
            if (sessionMaxAge == null || refreshTokenTtl == null || sessionMaxAge.compareTo(refreshTokenTtl) < 0) {
                errors.rejectValue("token.sessionMaxAge", "range",
                        "token.sessionMaxAge must not be shorter than token.refreshTokenTtl");
            }
            if (audience == null || audience.stream().noneMatch(value -> value != null && !value.isBlank())) {
                errors.rejectValue("token.audience", "required", "token.audience must contain at least one value");
            }
        }
    }
}
