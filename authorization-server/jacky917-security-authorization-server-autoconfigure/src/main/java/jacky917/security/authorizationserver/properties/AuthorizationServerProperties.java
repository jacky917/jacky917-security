package jacky917.security.authorizationserver.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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
