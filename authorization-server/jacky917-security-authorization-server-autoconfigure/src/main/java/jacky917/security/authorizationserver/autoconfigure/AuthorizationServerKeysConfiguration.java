package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.keys.JdbcSigningKeyStore;
import jacky917.security.authorizationserver.keys.KeyEncryptor;
import jacky917.security.authorizationserver.keys.RotatingJwkSource;
import jacky917.security.authorizationserver.keys.SigningKeyService;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Clock;

/**
 * Signing key configuration: storage, encryption, the published JWKS, and
 * the token encoder.
 * <p>
 * 簽章金鑰配置：儲存、加密、公開的 JWKS 與 token encoder。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerKeysConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    SigningKeyStore signingKeyStore(JdbcClient jdbcClient) {
        return new JdbcSigningKeyStore(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    KeyEncryptor keyEncryptor(AuthorizationServerProperties properties) {
        AuthorizationServerProperties.Keys keys = properties.getKeys();
        return new KeyEncryptor(keys.encryptionKeyBytes(), keys.getEncryptionKeyId());
    }

    @Bean
    @ConditionalOnMissingBean
    SigningKeyService signingKeyService(SigningKeyStore store, KeyEncryptor encryptor,
                                        AuthorizationServerProperties properties, Clock clock) {
        return new SigningKeyService(store, encryptor,
                JWSAlgorithm.parse(properties.getKeys().getAlgorithm().name()), clock);
    }

    /**
     * Creates the first signing key if needed and checks that the active
     * key can be decrypted, so a wrong master key fails startup.
     * <p>
     * 需要時建立第一把簽章金鑰，並確認目前的金鑰可以解密，主金鑰錯誤時讓啟動失敗。
     *
     * @param keys  the signing key service
     *              <br>簽章金鑰服務
     * @return the initializer
     *         <br>初始化器
     */
    @Bean
    @DependsOnDatabaseInitialization
    InitializingBean signingKeyInitializer(SigningKeyService keys) {
        return keys::ensureActiveKey;
    }

    /**
     * The JWKS published by the authorization server; public keys only.
     * <p>
     * Authorization Server 公開的 JWKS，只有公鑰。
     *
     * @param keys  the signing key service
     *              <br>簽章金鑰服務
     * @return the JWK source
     *         <br>JWK source
     */
    @Bean
    @ConditionalOnMissingBean
    JWKSource<SecurityContext> jwkSource(SigningKeyService keys) {
        return new RotatingJwkSource(keys);
    }

    /**
     * Signs tokens with the active key only. Spring Security's encoder
     * refuses to sign when several keys match, and several are published
     * during a rotation.
     * <p>
     * 只以目前的金鑰簽章。輪換期間會公開多把金鑰，而 Spring Security 的
     * encoder 在多把金鑰符合時會拒絕簽章。
     *
     * @param keys  the signing key service
     *              <br>簽章金鑰服務
     * @return the token encoder
     *         <br>token encoder
     */
    @Bean
    @ConditionalOnMissingBean
    JwtEncoder jwtEncoder(SigningKeyService keys) {
        return new NimbusJwtEncoder((selector, context) -> selector.select(new JWKSet(keys.activeSigningKey())));
    }

    @Bean
    @ConditionalOnMissingBean
    Clock authorizationServerClock() {
        return Clock.systemUTC();
    }
}
