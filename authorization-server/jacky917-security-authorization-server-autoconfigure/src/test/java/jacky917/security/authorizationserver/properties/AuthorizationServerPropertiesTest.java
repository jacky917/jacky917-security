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
    @DisplayName("停用時不驗證")
    void disabledSkipsValidation() {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.setEnabled(false);
        assertThat(validate(properties).hasErrors()).isFalse();
    }

    private static AuthorizationServerProperties withIssuer(String issuer) {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.setIssuer(URI.create(issuer));
        return properties;
    }

    private static Errors validate(AuthorizationServerProperties properties) {
        Errors errors = new BeanPropertyBindingResult(properties, "properties");
        properties.validate(properties, errors);
        return errors;
    }
}
