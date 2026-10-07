package jacky917.security.authorizationserver.keys;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("KeyEncryptor（AES-256-GCM）")
class KeyEncryptorTest {

    private static final byte[] KEY = new byte[32];
    private static final byte[] OTHER_KEY = filled((byte) 1);

    private final KeyEncryptor encryptor = new KeyEncryptor(KEY, "v1");

    @Test
    @DisplayName("加密後可還原；同一明文每次的密文不同（隨機 nonce）")
    void roundTrip() {
        String first = encryptor.encrypt("secret-jwk", "kid-1");
        String second = encryptor.encrypt("secret-jwk", "kid-1");
        assertThat(first).isNotEqualTo(second).doesNotContain("secret");
        assertThat(encryptor.decrypt(first, "kid-1", "v1")).isEqualTo("secret-jwk");
    }

    @Test
    @DisplayName("主金鑰錯誤時無法解密")
    void wrongMasterKeyFails() {
        String encrypted = encryptor.encrypt("secret-jwk", "kid-1");
        assertThatThrownBy(() -> new KeyEncryptor(OTHER_KEY, "v1").decrypt(encrypted, "kid-1", "v1"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("master key");
    }

    @Test
    @DisplayName("密文搬到其他 kid（附加驗證資料不同）時無法解密")
    void ciphertextIsBoundToKid() {
        String encrypted = encryptor.encrypt("secret-jwk", "kid-1");
        assertThatThrownBy(() -> encryptor.decrypt(encrypted, "kid-2", "v1")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("密文被竄改時無法解密")
    void tamperingIsDetected() {
        byte[] data = Base64.getDecoder().decode(encryptor.encrypt("secret-jwk", "kid-1"));
        data[data.length - 1] ^= 1;
        assertThatThrownBy(() -> encryptor.decrypt(Base64.getEncoder().encodeToString(data), "kid-1", "v1"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("主金鑰識別碼不同時，明確指出是哪一把主金鑰")
    void masterKeyIdMismatchIsReported() {
        String encrypted = encryptor.encrypt("secret-jwk", "kid-1");
        assertThatThrownBy(() -> new KeyEncryptor(KEY, "v2").decrypt(encrypted, "kid-1", "v1"))
                .hasMessageContaining("'v1'").hasMessageContaining("'v2'");
    }

    @Test
    @DisplayName("主金鑰必須是 32 bytes")
    void keyLength() {
        assertThatThrownBy(() -> new KeyEncryptor(new byte[16], "v1")).isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] filled(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
