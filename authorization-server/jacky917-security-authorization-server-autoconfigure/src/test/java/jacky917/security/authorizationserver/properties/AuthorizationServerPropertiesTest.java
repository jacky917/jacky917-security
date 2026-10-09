package jacky917.security.authorizationserver.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuthorizationServerProperties 驗證")
class AuthorizationServerPropertiesTest {

    @Test
    @DisplayName("預設值符合設計（詳細設計 §6）")
    void defaults() {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        assertThat(properties.isEnabled()).isTrue();
        assertThat(properties.getDatabase().getDialect()).isEqualTo(AuthorizationServerProperties.DialectType.AUTO);
        assertThat(properties.getToken().getAccessTokenTtl()).isEqualTo(Duration.ofMinutes(10));
        assertThat(properties.getToken().getRefreshTokenTtl()).isEqualTo(Duration.ofDays(14));
        assertThat(properties.getToken().getAuthorizationCodeTtl()).isEqualTo(Duration.ofMinutes(1));
        assertThat(properties.getToken().getSessionMaxAge()).isEqualTo(Duration.ofDays(90));
        assertThat(properties.getToken().getAudience()).containsExactly("jacky917-api");
        assertThat(properties.getKeys().getAlgorithm()).isEqualTo(AuthorizationServerProperties.SigningAlgorithm.RS256);
        assertThat(properties.getKeys().getEncryptionKeyId()).isEqualTo("v1");
        assertThat(properties.getRefresh().getReuseGracePeriod()).isEqualTo(Duration.ofSeconds(30));
        assertThat(properties.getRefresh().getHistoryRetention()).isEqualTo(Duration.ofHours(24));
        assertThat(properties.getLoginProtection().getMaxFailures()).isEqualTo(5);
        assertThat(properties.getLoginProtection().getLockDuration()).isEqualTo(Duration.ofMinutes(15));
        assertThat(properties.getLoginProtection().getMaxFailuresPerIpPerMinute()).isEqualTo(20);
        assertThat(properties.getKeys().getRotationPeriod()).isEqualTo(Duration.ofDays(90));
        assertThat(properties.getKeys().getAnnouncePeriod()).isEqualTo(Duration.ofDays(1));
        assertThat(properties.getCleanup().isEnabled()).isTrue();
        assertThat(properties.getCleanup().getBatchSize()).isEqualTo(1000);
        assertThat(properties.getCleanup().getLoginAuditRetention()).isEqualTo(Duration.ofDays(180));
    }

    @Test
    @DisplayName("未設定 issuer 時驗證失敗")
    void issuerIsRequired() {
        assertThat(validate(new AuthorizationServerProperties()).getFieldError("issuer")).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://auth.example.com", "http://localhost:9000", "http://127.0.0.1:9000/as"})
    @DisplayName("https 或 localhost 的 http 可通過")
    void validIssuers(String issuer) {
        assertThat(validate(withIssuer(issuer)).hasErrors()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://auth.example.com", "auth.example.com", "https://auth.example.com?x=1"})
    @DisplayName("非 localhost 的 http、相對網址、含 query 的 issuer 會被拒絕")
    void invalidIssuers(String issuer) {
        assertThat(validate(withIssuer(issuer)).getFieldError("issuer")).isNotNull();
    }

    @Test
    @DisplayName("Token 有效期超出範圍、Session 上限短於 Refresh Token、audience 為空時被拒絕")
    void tokenRanges() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getToken().setAccessTokenTtl(Duration.ofHours(2));
        properties.getToken().setAuthorizationCodeTtl(Duration.ofSeconds(10));
        properties.getToken().setSessionMaxAge(Duration.ofDays(1));
        properties.getToken().setAudience(List.of(" "));
        Errors errors = validate(properties);
        assertThat(errors.getFieldErrors()).extracting(error -> error.getField()).containsExactlyInAnyOrder(
                "token.accessTokenTtl", "token.authorizationCodeTtl", "token.sessionMaxAge", "token.audience");
    }

    @Test
    @DisplayName("寬限期超過 2 分鐘、保留期短於 1 小時或長於 Refresh Token 有效期時被拒絕")
    void refreshRanges() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getRefresh().setReuseGracePeriod(Duration.ofMinutes(3));
        properties.getRefresh().setHistoryRetention(Duration.ofMinutes(30));
        assertThat(validate(properties).getFieldErrors()).extracting(error -> error.getField())
                .containsExactlyInAnyOrder("refresh.reuseGracePeriod", "refresh.historyRetention");

        properties.getRefresh().setReuseGracePeriod(Duration.ZERO);
        properties.getRefresh().setHistoryRetention(Duration.ofDays(15));
        assertThat(validate(properties).getFieldErrors()).extracting(error -> error.getField())
                .containsExactly("refresh.historyRetention");
    }

    @Test
    @DisplayName("登入保護：失敗次數 1～20、鎖定 1 分鐘～24 小時、IP 上限 1～10000")
    void loginProtectionRanges() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getLoginProtection().setMaxFailures(0);
        properties.getLoginProtection().setLockDuration(Duration.ofSeconds(30));
        properties.getLoginProtection().setMaxFailuresPerIpPerMinute(0);
        assertThat(validate(properties).getFieldErrors()).extracting(error -> error.getField()).containsExactlyInAnyOrder(
                "loginProtection.maxFailures", "loginProtection.lockDuration", "loginProtection.maxFailuresPerIpPerMinute");
    }

    @Test
    @DisplayName("金鑰輪換：週期至少 7 天、公開期間至少 5 分鐘且短於週期；清理：批次 10～10000、保留期至少 1 天")
    void rotationAndCleanupRanges() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getKeys().setRotationPeriod(Duration.ofDays(6));
        properties.getKeys().setAnnouncePeriod(Duration.ofDays(6));
        properties.getCleanup().setBatchSize(5);
        properties.getCleanup().setLoginAuditRetention(Duration.ofHours(1));
        assertThat(validate(properties).getFieldErrors()).extracting(error -> error.getField()).containsExactlyInAnyOrder(
                "keys.rotationPeriod", "keys.announcePeriod", "cleanup.batchSize", "cleanup.loginAuditRetention");
    }

    @Test
    @DisplayName("停用時不驗證")
    void disabledSkipsValidation() {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.setEnabled(false);
        assertThat(validate(properties).hasErrors()).isFalse();
    }

    @Test
    @DisplayName("主金鑰必填，且必須是 32 bytes 的 Base64")
    void encryptionKey() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getKeys().setEncryptionKey(null);
        assertThat(validate(properties).getFieldError("keys.encryptionKey").getDefaultMessage())
                .contains("openssl rand -base64 32");
        properties.getKeys().setEncryptionKey("c2hvcnQ=");
        assertThat(validate(properties).getFieldError("keys.encryptionKey").getDefaultMessage()).contains("32 bytes");
        properties.getKeys().setEncryptionKey("not base64!");
        assertThat(validate(properties).getFieldError("keys.encryptionKey").getDefaultMessage()).contains("Base64");
    }

    @Test
    @DisplayName("Client 規則：redirect URI、grant type 組合、public client、client id 格式、第三方")
    void clientRules() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        AuthorizationServerProperties.Client noRedirect = new AuthorizationServerProperties.Client();
        properties.getClients().put("no-redirect", noRedirect);
        AuthorizationServerProperties.Client insecure = new AuthorizationServerProperties.Client();
        insecure.setRedirectUris(List.of("http://app.example.com/cb", "https://app.example.com/cb#x", "myapp:/cb"));
        properties.getClients().put("insecure", insecure);
        AuthorizationServerProperties.Client publicWithRefresh = new AuthorizationServerProperties.Client();
        publicWithRefresh.setAuthenticationMethod(AuthorizationServerProperties.AuthenticationMethod.NONE);
        publicWithRefresh.setRedirectUris(List.of("https://app.example.com/cb"));
        properties.getClients().put("public-refresh", publicWithRefresh);
        AuthorizationServerProperties.Client batchWithOpenid = new AuthorizationServerProperties.Client();
        batchWithOpenid.setGrantTypes(Set.of(AuthorizationServerProperties.GrantType.CLIENT_CREDENTIALS));
        properties.getClients().put("batch", batchWithOpenid);
        AuthorizationServerProperties.Client thirdParty = new AuthorizationServerProperties.Client();
        thirdParty.setTrustLevel(jacky917.security.core.TrustLevel.THIRD_PARTY);
        thirdParty.setRedirectUris(List.of("https://partner.example.com/cb"));
        properties.getClients().put("partner", thirdParty);
        AuthorizationServerProperties.Client noop = new AuthorizationServerProperties.Client();
        noop.setSecret("{noop}secret");
        noop.setRedirectUris(List.of("https://app.example.com/cb"));
        properties.getClients().put("noop", noop);
        properties.getClients().put("Bad Id", validClient());

        List<String> messages = validate(properties).getAllErrors().stream().map(error -> error.getDefaultMessage()).toList();
        assertThat(messages).anyMatch(m -> m.startsWith("clients[no-redirect]") && m.contains("requires redirect-uris"));
        assertThat(messages).anyMatch(m -> m.contains("http://app.example.com/cb must be an absolute https URL"));
        assertThat(messages).anyMatch(m -> m.contains("https://app.example.com/cb#x"));
        assertThat(messages).anyMatch(m -> m.contains("redirect URI myapp:/cb"));
        assertThat(messages).anyMatch(m -> m.startsWith("clients[public-refresh]") && m.contains("never receives refresh tokens"));
        assertThat(messages).anyMatch(m -> m.startsWith("clients[batch]") && m.contains("openid scope requires authorization_code"));
        assertThat(messages).anyMatch(m -> m.startsWith("clients[partner]") && m.contains("requires privacy-policy-url"));
        assertThat(messages).anyMatch(m -> m.startsWith("clients[noop]") && m.contains("{bcrypt}"));
        assertThat(messages).anyMatch(m -> m.startsWith("clients[Bad Id]") && m.contains("client id"));
        assertThat(messages).hasSize(9);
    }

    @Test
    @DisplayName("第三方 client（D30）：不可使用 client_credentials 與 as: scope；網址必須是 https；合法的第三方設定可通過")
    void thirdPartyClientRules() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        AuthorizationServerProperties.Client partner = thirdPartyClient();
        partner.setGrantTypes(Set.of(AuthorizationServerProperties.GrantType.AUTHORIZATION_CODE,
                AuthorizationServerProperties.GrantType.CLIENT_CREDENTIALS));
        partner.setScopes(Set.of("openid", "as:user:read"));
        partner.setLogoUrl("http://partner.example.com/logo.png");
        properties.getClients().put("partner", partner);

        List<String> messages = validate(properties).getAllErrors().stream().map(error -> error.getDefaultMessage()).toList();
        assertThat(messages).anyMatch(m -> m.contains("cannot use client_credentials"));
        assertThat(messages).anyMatch(m -> m.contains("cannot ask for as:user:read"));
        assertThat(messages).anyMatch(m -> m.contains("logo-url must be an absolute https URL"));
        assertThat(messages).hasSize(3);

        AuthorizationServerProperties valid = withIssuer("https://auth.example.com");
        valid.getClients().put("partner", thirdPartyClient());
        AuthorizationServerProperties.Client publicPartner = thirdPartyClient();
        publicPartner.setAuthenticationMethod(AuthorizationServerProperties.AuthenticationMethod.NONE);
        publicPartner.setSecret(null);
        publicPartner.setGrantTypes(Set.of(AuthorizationServerProperties.GrantType.AUTHORIZATION_CODE));
        valid.getClients().put("partner-app", publicPartner);
        assertThat(validate(valid).hasErrors()).isFalse();
    }

    private static AuthorizationServerProperties.Client thirdPartyClient() {
        AuthorizationServerProperties.Client client = validClient();
        client.setTrustLevel(jacky917.security.core.TrustLevel.THIRD_PARTY);
        client.setPrivacyPolicyUrl("https://partner.example.com/privacy");
        client.setTermsUrl("https://partner.example.com/terms");
        client.setLogoUrl("https://partner.example.com/logo.png");
        return client;
    }

    @Test
    @DisplayName("合法的 client 設定與 localhost 的 http redirect 可通過")
    void validClientPasses() {
        AuthorizationServerProperties properties = withIssuer("https://auth.example.com");
        properties.getClients().put("web-bff", validClient());
        AuthorizationServerProperties.Client local = validClient();
        local.setRedirectUris(List.of("http://localhost:8080/login/oauth2/code/jacky917", "com.example.app:/callback"));
        properties.getClients().put("local-bff", local);
        assertThat(validate(properties).hasErrors()).isFalse();
    }

    private static AuthorizationServerProperties.Client validClient() {
        AuthorizationServerProperties.Client client = new AuthorizationServerProperties.Client();
        client.setSecret("${WEB_BFF_SECRET}");
        client.setRedirectUris(List.of("https://app.example.com/login/oauth2/code/jacky917"));
        return client;
    }

    private static AuthorizationServerProperties withIssuer(String issuer) {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.setIssuer(URI.create(issuer));
        properties.getKeys().setEncryptionKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=");
        return properties;
    }

    private static Errors validate(AuthorizationServerProperties properties) {
        Errors errors = new BeanPropertyBindingResult(properties, "properties");
        properties.validate(properties, errors);
        return errors;
    }
}
