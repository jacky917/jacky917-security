package jacky917.security.authorizationserver.keys;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Encrypts private signing keys with AES-256-GCM before they are stored.
 * <p>
 * 在儲存前以 AES-256-GCM 加密簽章私鑰。
 * <p>
 * The output is Base64 of a 12-byte random nonce followed by the
 * ciphertext and the authentication tag. The key id is bound as associated
 * data, so a ciphertext copied to another row fails to decrypt.
 * <p>
 * 輸出為 Base64：12 bytes 的隨機 nonce，接著是密文與驗證標籤。金鑰識別碼作為
 * 附加驗證資料，密文被複製到其他列時會無法解密。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class KeyEncryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey masterKey;
    private final String masterKeyId;
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates an encryptor with the given master key.
     * <p>
     * 以指定的主金鑰建立加密器。
     *
     * @param masterKey    the 32-byte AES key
     *                     <br>32 bytes 的 AES 金鑰
     * @param masterKeyId  the id stored with each encrypted key
     *                     <br>與每把加密金鑰一起儲存的識別碼
     * @throws IllegalArgumentException if the key is not 32 bytes
     *         <br>金鑰長度不是 32 bytes 時
     */
    public KeyEncryptor(byte[] masterKey, String masterKeyId) {
        if (masterKey.length != 32) {
            throw new IllegalArgumentException("The master key must be 32 bytes (AES-256)");
        }
        this.masterKey = new SecretKeySpec(masterKey, "AES");
        this.masterKeyId = masterKeyId;
    }

    /**
     * Returns the id of the master key.
     * <p>
     * 回傳主金鑰的識別碼。
     *
     * @return the master key id
     *         <br>主金鑰識別碼
     */
    public String masterKeyId() {
        return masterKeyId;
    }

    /**
     * Encrypts a private key.
     * <p>
     * 加密私鑰。
     *
     * @param plaintext  the private key, for example a JWK in JSON
     *                   <br>私鑰，例如 JSON 格式的 JWK
     * @param kid        the key id, bound as associated data
     *                   <br>金鑰識別碼，作為附加驗證資料
     * @return the Base64 nonce and ciphertext
     *         <br>Base64 的 nonce 與密文
     */
    public String encrypt(String plaintext, String kid) {
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(nonce.length + ciphertext.length).put(nonce).put(ciphertext).array());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Cannot encrypt the signing key " + kid, ex);
        }
    }

    /**
     * Decrypts a private key.
     * <p>
     * 解密私鑰。
     *
     * @param encrypted        the value returned by {@link #encrypt}
     *                         <br>{@link #encrypt} 的回傳值
     * @param kid              the key id it was encrypted with
     *                         <br>加密時使用的金鑰識別碼
     * @param encryptionKeyId  the master key id stored with the key
     *                         <br>與金鑰一起儲存的主金鑰識別碼
     * @return the private key
     *         <br>私鑰
     * @throws IllegalStateException if the master key id differs, or the
     *         master key is wrong or the data was altered
     *         <br>主金鑰識別碼不同、主金鑰錯誤或資料遭竄改時
     */
    public String decrypt(String encrypted, String kid, String encryptionKeyId) {
        if (!masterKeyId.equals(encryptionKeyId)) {
            throw new IllegalStateException("Signing key " + kid + " was encrypted with master key '" + encryptionKeyId
                    + "', but the configured master key is '" + masterKeyId + "'");
        }
        try {
            byte[] data = Base64.getDecoder().decode(encrypted);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_LENGTH));
            cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));
            byte[] plaintext = cipher.doFinal(data, NONCE_LENGTH, data.length - NONCE_LENGTH);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Cannot decrypt signing key " + kid
                    + ": the master key (keys.encryption-key) is wrong or the stored key was altered", ex);
        }
    }
}
