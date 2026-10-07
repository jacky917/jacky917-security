package jacky917.security.authorizationserver.keys;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Loads, caches, and creates signing keys.
 * <p>
 * 讀取、快取並建立簽章金鑰。
 * <p>
 * Keys change rarely, so they are cached for {@link #CACHE_TTL}. Another
 * instance's rotation is therefore picked up within that time; until then
 * this instance keeps signing with the previous key, which is still
 * published as {@code RETIRING}.
 * <p>
 * 金鑰很少變動，因此快取 {@link #CACHE_TTL}。其他實例輪換金鑰後，本實例最晚
 * 在這段時間內更新；在此之前仍以前一把金鑰簽章，而它此時仍以 {@code RETIRING}
 * 公開，簽出的 token 依然可以驗證。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class SigningKeyService {

    /**
     * How long loaded keys are reused before the store is read again.
     * <p>
     * 已讀取的金鑰在重新讀取前可重複使用的時間。
     */
    public static final Duration CACHE_TTL = Duration.ofMinutes(1);

    private final SigningKeyStore store;
    private final KeyEncryptor encryptor;
    private final JWSAlgorithm algorithm;
    private final Clock clock;

    private volatile Snapshot snapshot;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param store      where keys are stored
     *                   <br>金鑰的儲存位置
     * @param encryptor  encrypts and decrypts private keys
     *                   <br>加解密私鑰
     * @param algorithm  the algorithm of new keys, {@code RS256} or
     *                   {@code ES256}
     *                   <br>新金鑰的演算法，{@code RS256} 或 {@code ES256}
     * @param clock      the clock for timestamps
     *                   <br>用於時間戳記的時鐘
     */
    public SigningKeyService(SigningKeyStore store, KeyEncryptor encryptor, JWSAlgorithm algorithm, Clock clock) {
        if (!JWSAlgorithm.RS256.equals(algorithm) && !JWSAlgorithm.ES256.equals(algorithm)) {
            throw new IllegalArgumentException("Unsupported signing algorithm " + algorithm);
        }
        this.store = store;
        this.encryptor = encryptor;
        this.algorithm = algorithm;
        this.clock = clock;
    }

    /**
     * Creates an {@code ACTIVE} key when none exists, then checks that the
     * active key can be decrypted. Called once at startup, so a wrong
     * master key fails startup instead of the first token request.
     * <p>
     * 沒有 {@code ACTIVE} 金鑰時建立一把，再確認目前的金鑰可以解密。於啟動時
     * 呼叫一次，主金鑰錯誤時會讓啟動失敗，而不是等到第一次簽發 token。
     */
    public void ensureActiveKey() {
        if (store.findActive().isEmpty()) {
            SigningKey key = generate(SigningKeyStatus.ACTIVE);
            try {
                store.save(key);
                log.info("Created the first signing key {} ({})", key.kid(), key.algorithm());
            } catch (DuplicateKeyException ex) {
                // 另一個實例同時建立了 ACTIVE 金鑰；唯一索引擋下本實例的金鑰，改用對方的
                log.info("Another instance created the first signing key; using it");
            }
        }
        snapshot = null;
        activeSigningKey();
    }

    /**
     * Generates a new key with the configured algorithm.
     * <p>
     * 以設定的演算法產生新的金鑰。
     *
     * @param status  the initial status, {@code NEXT} or {@code ACTIVE}
     *                <br>初始狀態，{@code NEXT} 或 {@code ACTIVE}
     * @return the new key, with its private key encrypted
     *         <br>新的金鑰，私鑰已加密
     */
    public SigningKey generate(SigningKeyStatus status) {
        String kid = UUID.randomUUID().toString();
        Instant now = clock.instant();
        JWK jwk;
        int size;
        try {
            if (JWSAlgorithm.RS256.equals(algorithm)) {
                size = 3072;
                jwk = new RSAKeyGenerator(size).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(algorithm).generate();
            } else {
                size = 256;
                jwk = new ECKeyGenerator(Curve.P_256).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(algorithm).generate();
            }
        } catch (JOSEException ex) {
            throw new IllegalStateException("Cannot generate a signing key", ex);
        }
        return new SigningKey(kid, algorithm.getName(), size, jwk.toPublicJWK().toJSONString(),
                encryptor.encrypt(jwk.toJSONString(), kid), encryptor.masterKeyId(), status, now,
                status == SigningKeyStatus.ACTIVE ? now : null, null, null);
    }

    /**
     * Returns the private JWK that signs new tokens.
     * <p>
     * 回傳用來簽發新 token 的私鑰 JWK。
     *
     * @return the active private key
     *         <br>目前的私鑰
     * @throws IllegalStateException if there is no active key
     *         <br>沒有 {@code ACTIVE} 金鑰時
     */
    public JWK activeSigningKey() {
        return current().active();
    }

    /**
     * Returns the public JWKs published in the JWKS.
     * <p>
     * 回傳公開於 JWKS 的公鑰 JWK。
     *
     * @return the publishable public keys
     *         <br>可公開的公鑰
     */
    public List<JWK> publishableKeys() {
        return current().publishable();
    }

    /**
     * Discards the cached keys, so the next call reads the store.
     * <p>
     * 清除快取，下一次呼叫時重新讀取。
     */
    public void evictCache() {
        snapshot = null;
    }

    private Snapshot current() {
        Snapshot cached = snapshot;
        Instant now = clock.instant();
        if (cached != null && now.isBefore(cached.loadedAt().plus(CACHE_TTL))) {
            return cached;
        }
        SigningKey active = store.findActive()
                .orElseThrow(() -> new IllegalStateException("There is no ACTIVE signing key"));
        List<JWK> publishable = store.findPublishable().stream().map(key -> parse(key.publicJwk(), key.kid())).toList();
        JWK activeJwk = parse(encryptor.decrypt(active.privateKeyEncrypted(), active.kid(), active.encryptionKeyId()),
                active.kid());
        if (!(activeJwk instanceof RSAKey || activeJwk instanceof ECKey) || !activeJwk.isPrivate()) {
            throw new IllegalStateException("Signing key " + active.kid() + " does not contain a private key");
        }
        Snapshot loaded = new Snapshot(activeJwk, publishable, now);
        snapshot = loaded;
        return loaded;
    }

    private static JWK parse(String json, String kid) {
        try {
            return JWK.parse(json);
        } catch (ParseException ex) {
            throw new IllegalStateException("Signing key " + kid + " is not a valid JWK", ex);
        }
    }

    private record Snapshot(JWK active, List<JWK> publishable, Instant loadedAt) {
    }
}
