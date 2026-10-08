package jacky917.security.authorizationserver.keys;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * A signing key as stored in the {@code signing_key} table.
 * <p>
 * 儲存於 {@code signing_key} 表中的簽章金鑰。
 *
 * @param kid                  the key id, published as the JWK {@code kid}
 *                             <br>金鑰識別碼，即 JWK 的 {@code kid}
 * @param algorithm            the JWS algorithm, {@code RS256} or
 *                             {@code ES256}
 *                             <br>JWS 演算法，{@code RS256} 或 {@code ES256}
 * @param keySize              the key size in bits
 *                             <br>金鑰長度（位元）
 * @param publicJwk            the public JWK as JSON
 *                             <br>公鑰的 JWK JSON
 * @param privateKeyEncrypted  the private JWK encrypted by
 *                             {@link KeyEncryptor}
 *                             <br>以 {@link KeyEncryptor} 加密後的私鑰 JWK
 * @param encryptionKeyId      the id of the master key that encrypted the
 *                             private key
 *                             <br>加密私鑰所用主金鑰的識別碼
 * @param status               the lifecycle status
 *                             <br>生命週期狀態
 * @param createdAt            when the key was generated
 *                             <br>產生時間
 * @param activatedAt          when the key became {@code ACTIVE}
 *                             <br>成為 {@code ACTIVE} 的時間
 * @param retiringAt           when the key became {@code RETIRING}
 *                             <br>成為 {@code RETIRING} 的時間
 * @param retiredAt            when the key became {@code RETIRED}
 *                             <br>成為 {@code RETIRED} 的時間
 * @author Jacky
 * @since 2.1.0
 */
public record SigningKey(
        String kid,
        String algorithm,
        int keySize,
        String publicJwk,
        String privateKeyEncrypted,
        String encryptionKeyId,
        SigningKeyStatus status,
        Instant createdAt,
        @Nullable Instant activatedAt,
        @Nullable Instant retiringAt,
        @Nullable Instant retiredAt) {
}
