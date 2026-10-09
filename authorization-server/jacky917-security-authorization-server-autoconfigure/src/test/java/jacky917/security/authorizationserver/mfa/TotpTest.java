package jacky917.security.authorizationserver.mfa;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TOTP（RFC 6238）與 QR code。
 */
class TotpTest {

    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "{0} 秒 → {1}")
    @CsvSource({"59, 94287082", "1111111109, 07081804", "1111111111, 14050471", "1234567890, 89005924",
            "2000000000, 69279037", "20000000000, 65353130"})
    @DisplayName("RFC 6238 附錄 B 的 SHA-1 測試向量")
    void matchesTheRfcTestVectors(long seconds, String expected) {
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(seconds)), 8, "HmacSHA1"))
                .isEqualTo(expected);
    }

    @Test
    @DisplayName("Base32 編碼可還原；6 位數的驗證碼與 RFC 向量的後 6 位相同")
    void encodesSecretsInBase32() {
        String secret = Totp.encode(RFC_SECRET);
        assertThat(secret).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assertThat(Totp.decode(secret)).isEqualTo(RFC_SECRET);
        assertThat(Totp.code(secret, Totp.step(Instant.ofEpochSecond(59)))).isEqualTo("287082");
        assertThat(Totp.newSecret()).hasSize(32).matches("[A-Z2-7]+");
    }

    @Test
    @DisplayName("前後各容許一個時間步；已使用的時間步不再接受；格式錯誤不接受")
    void verifiesWithinOneStepAndOnlyOnce() {
        String secret = Totp.newSecret();
        Instant now = Instant.parse("2026-10-09T00:00:15Z");
        long step = Totp.step(now);
        assertThat(Totp.verify(secret, Totp.code(secret, step), now, 0)).hasValue(step);
        assertThat(Totp.verify(secret, Totp.code(secret, step - 1), now, 0)).hasValue(step - 1);
        assertThat(Totp.verify(secret, Totp.code(secret, step + 1), now, 0)).hasValue(step + 1);
        assertThat(Totp.verify(secret, Totp.code(secret, step - 2), now, 0)).isEmpty();
        assertThat(Totp.verify(secret, Totp.code(secret, step), now, step)).as("已使用").isEmpty();
        String code = Totp.code(secret, step);
        assertThat(Totp.verify(secret, code.substring(0, 3) + " " + code.substring(3), now, 0)).hasValue(step);
        assertThat(Totp.verify(secret, "12345", now, 0)).isEmpty();
        assertThat(Totp.verify(secret, "abcdef", now, 0)).isEmpty();
    }

    @Test
    @DisplayName("otpauth 網址與 SVG 的 QR code")
    void buildsTheQrCode() {
        String uri = Totp.uri("My App", "alice@example.com", "ABC");
        assertThat(uri).isEqualTo("otpauth://totp/My%20App:alice%40example.com?secret=ABC&issuer=My%20App"
                + "&algorithm=SHA1&digits=6&period=30");
        String image = QrCodes.svgDataUri(uri);
        assertThat(image).startsWith("data:image/svg+xml;base64,");
        String svg = new String(Base64.getDecoder().decode(image.substring(image.indexOf(',') + 1)),
                StandardCharsets.UTF_8);
        assertThat(svg).startsWith("<svg").contains("<path fill=\"#000\" d=\"M");
    }
}
