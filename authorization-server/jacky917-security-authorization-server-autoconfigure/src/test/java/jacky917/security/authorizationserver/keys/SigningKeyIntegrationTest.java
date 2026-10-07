package jacky917.security.authorizationserver.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 簽章金鑰：首次啟動自動產生、私鑰加密儲存、主金鑰錯誤時啟動失敗、輪換期間公開多把金鑰但只以 ACTIVE 簽章
 * （詳細設計 T-KEY-01、T-KEY-03）。
 */
@DisplayName("簽章金鑰整合測試（SQLite／PostgreSQL）")
class SigningKeyIntegrationTest {

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("首次啟動產生 ACTIVE 金鑰；私鑰以密文儲存；簽出的 token 帶 kid 並可用 JWKS 驗證")
    void firstStartupCreatesActiveKey(String vendor) {
        TestDatabases.runner(vendor).run(context -> {
            assertThat(context).hasNotFailed();
            JdbcClient jdbc = context.getBean(JdbcClient.class);
            assertThat(jdbc.sql("SELECT status FROM signing_key").query(String.class).list()).containsExactly("ACTIVE");
            String kid = jdbc.sql("SELECT kid FROM signing_key").query(String.class).single();
            String publicKey = jdbc.sql("SELECT public_key FROM signing_key").query(String.class).single();
            String privateKey = jdbc.sql("SELECT private_key_encrypted FROM signing_key").query(String.class).single();
            assertThat(publicKey).contains(kid).doesNotContain("\"d\"");
            assertThat(privateKey).doesNotContain("\"d\"").doesNotContain(kid);

            assertThat(publishedKids(context)).containsExactly(kid);
            Jwt jwt = sign(context);
            assertThat(jwt.getHeaders()).containsEntry("kid", kid);
            assertThat(verify(context, jwt).getSubject()).isEqualTo("user-1");
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("重新啟動沿用既有金鑰；主金鑰錯誤時啟動失敗")
    void restartReusesKeyAndWrongMasterKeyFails(String vendor) {
        String url = TestDatabases.newDatabaseUrl(vendor);
        String[] kid = new String[1];
        TestDatabases.runner(vendor, url).run(context ->
                kid[0] = context.getBean(JdbcClient.class).sql("SELECT kid FROM signing_key").query(String.class).single());

        TestDatabases.runner(vendor, url).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JdbcClient.class).sql("SELECT kid FROM signing_key")
                    .query(String.class).list()).containsExactly(kid[0]);
        });

        TestDatabases.runner(vendor, url)
                .withPropertyValues("jacky917.security.authorization-server.keys.encryption-key="
                        + "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("Cannot decrypt signing key " + kid[0])
                        .hasStackTraceContaining("keys.encryption-key"));
    }

    @Test
    @DisplayName("輪換期間：JWKS 公開 NEXT、ACTIVE、RETIRING，不公開 RETIRED；只以 ACTIVE 簽章")
    void rotationPublishesSeveralKeysButSignsWithActiveOnly() {
        TestDatabases.runner(TestDatabases.SQLITE).run(context -> {
            SigningKeyService service = context.getBean(SigningKeyService.class);
            SigningKeyStore store = context.getBean(SigningKeyStore.class);
            String active = store.findActive().orElseThrow().kid();
            SigningKey next = service.generate(SigningKeyStatus.NEXT);
            store.save(next);
            SigningKey retiring = service.generate(SigningKeyStatus.NEXT);
            SigningKey retired = service.generate(SigningKeyStatus.NEXT);
            store.save(new SigningKey(retiring.kid(), retiring.algorithm(), retiring.keySize(), retiring.publicJwk(),
                    retiring.privateKeyEncrypted(), retiring.encryptionKeyId(), SigningKeyStatus.RETIRING,
                    retiring.createdAt(), null, Instant.now(), null));
            store.save(new SigningKey(retired.kid(), retired.algorithm(), retired.keySize(), retired.publicJwk(),
                    retired.privateKeyEncrypted(), retired.encryptionKeyId(), SigningKeyStatus.RETIRED,
                    retired.createdAt(), null, null, Instant.now()));
            service.evictCache();

            assertThat(publishedKids(context)).containsExactlyInAnyOrder(active, next.kid(), retiring.kid());
            assertThat(sign(context).getHeaders()).containsEntry("kid", active);

            // 輪換：NEXT 成為 ACTIVE 後改以新金鑰簽章，舊金鑰簽的 token 仍可驗證
            Jwt before = sign(context);
            assertThat(store.transition(active, SigningKeyStatus.ACTIVE, SigningKeyStatus.RETIRING, Instant.now())).isTrue();
            assertThat(store.transition(next.kid(), SigningKeyStatus.NEXT, SigningKeyStatus.ACTIVE, Instant.now())).isTrue();
            assertThat(store.transition(next.kid(), SigningKeyStatus.NEXT, SigningKeyStatus.ACTIVE, Instant.now())).isFalse();
            service.evictCache();
            assertThat(sign(context).getHeaders()).containsEntry("kid", next.kid());
            assertThat(verify(context, before).getSubject()).isEqualTo("user-1");
        });
    }

    @Test
    @DisplayName("ES256 金鑰")
    void es256() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("jacky917.security.authorization-server.keys.algorithm=es256")
                .run(context -> {
                    assertThat(context.getBean(JdbcClient.class).sql("SELECT algorithm FROM signing_key")
                            .query(String.class).single()).isEqualTo("ES256");
                    Jwt jwt = context.getBean(JwtEncoder.class).encode(JwtEncoderParameters.from(
                            JwsHeader.with(SignatureAlgorithm.ES256).build(),
                            JwtClaimsSet.builder().subject("user-1").build()));
                    assertThat(verify(context, jwt).getSubject()).isEqualTo("user-1");
                });
    }

    @SuppressWarnings("unchecked")
    private static List<String> publishedKids(ApplicationContext context) throws Exception {
        JWKSource<SecurityContext> source = context.getBean(JWKSource.class);
        List<JWK> keys = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertThat(keys).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
        return keys.stream().map(JWK::getKeyID).toList();
    }

    private static Jwt sign(ApplicationContext context) {
        return context.getBean(JwtEncoder.class).encode(JwtEncoderParameters.from(
                JwtClaimsSet.builder().issuer("http://localhost:9000").subject("user-1").build()));
    }

    @SuppressWarnings("unchecked")
    private static Jwt verify(ApplicationContext context, Jwt jwt) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(context.getBean(JWKSource.class))
                .jwsAlgorithms(algorithms -> {
                    algorithms.add(SignatureAlgorithm.RS256);
                    algorithms.add(SignatureAlgorithm.ES256);
                }).build();
        return decoder.decode(jwt.getTokenValue());
    }
}
