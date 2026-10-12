package jacky917.security.authorizationserver.mfa;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.OptionalLong;

/**
 * Time-based one-time passwords (RFC 6238) as authenticator apps compute
 * them: HMAC-SHA1, 30-second steps and 6 digits (D31).
 * <p>
 * 驗證器 App 使用的時間型一次性密碼（RFC 6238）：HMAC-SHA1、30 秒為一個時間
 * 步、6 位數（D31）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class Totp {

    /**
     * The length of a step in seconds.
     * <p>
     * 一個時間步的秒數。
     */
    public static final long STEP_SECONDS = 30;

    private static final int DIGITS = 6;
    private static final int SECRET_BYTES = 20;
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
    }

    /**
     * Creates a random 160-bit secret, Base32 encoded as authenticator apps
     * expect.
     * <p>
     * 產生隨機的 160 位元密鑰，以驗證器 App 使用的 Base32 編碼。
     *
     * @return the secret
     *         <br>密鑰
     */
    public static String newSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return encode(secret);
    }

    /**
     * Returns the step that contains an instant.
     * <p>
     * 回傳某個時間所在的時間步。
     *
     * @param time  the instant
     *              <br>時間
     * @return the number of 30-second steps since the epoch
     *         <br>從 epoch 起的 30 秒時間步數
     */
    public static long step(Instant time) {
        return Math.floorDiv(time.getEpochSecond(), STEP_SECONDS);
    }

    /**
     * Returns the code of a step.
     * <p>
     * 回傳某個時間步的驗證碼。
     *
     * @param secret  the Base32 secret
     *                <br>Base32 編碼的密鑰
     * @param step    the step
     *                <br>時間步
     * @return the 6-digit code
     *         <br>6 位數的驗證碼
     */
    public static String code(String secret, long step) {
        return code(decode(secret), step, DIGITS, "HmacSHA1");
    }

    /**
     * Finds the step of a code: the current step, or the one before or
     * after it to allow for clock drift. A step at or before
     * {@code lastUsedStep} never matches, so a code works only once
     * (RFC 6238 §5.2).
     * <p>
     * 找出驗證碼所屬的時間步：目前的時間步，或前後各一個以容許時鐘誤差。等於
     * 或早於 {@code lastUsedStep} 的時間步一律不符，因此驗證碼只能使用一次
     * （RFC 6238 §5.2）。
     *
     * @param secret        the Base32 secret
     *                      <br>Base32 編碼的密鑰
     * @param code          the code the user typed; spaces are ignored
     *                      <br>使用者輸入的驗證碼，忽略空白
     * @param now           the current time
     *                      <br>目前時間
     * @param lastUsedStep  the step of the last accepted code, or 0
     *                      <br>上一次接受的驗證碼的時間步，或 0
     * @return the matching step, or empty if the code is wrong or used
     *         <br>相符的時間步；驗證碼錯誤或已使用時為空
     */
    public static OptionalLong verify(String secret, String code, Instant now, long lastUsedStep) {
        String typed = code.replace(" ", "");
        if (typed.length() != DIGITS || !typed.chars().allMatch(Character::isDigit)) {
            return OptionalLong.empty();
        }
        byte[] key = decode(secret);
        long current = step(now);
        for (long step = current - 1; step <= current + 1; step++) {
            if (step > lastUsedStep && MessageDigest.isEqual(code(key, step, DIGITS, "HmacSHA1")
                    .getBytes(StandardCharsets.US_ASCII), typed.getBytes(StandardCharsets.US_ASCII))) {
                return OptionalLong.of(step);
            }
        }
        return OptionalLong.empty();
    }

    /**
     * Returns the {@code otpauth://} address that authenticator apps read
     * from a QR code.
     * <p>
     * 回傳驗證器 App 從 QR code 讀取的 {@code otpauth://} 網址。
     *
     * @param issuer   the name the app shows, for example the product name
     *                 <br>App 顯示的名稱，例如產品名稱
     * @param account  the account the app shows, for example the email
     *                 <br>App 顯示的帳號，例如 Email
     * @param secret   the Base32 secret
     *                 <br>Base32 編碼的密鑰
     * @return the address
     *         <br>網址
     */
    public static String uri(String issuer, String account, String secret) {
        String label = encodeUri(issuer) + ":" + encodeUri(account);
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + encodeUri(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    static String code(byte[] key, long step, int digits, String algorithm) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            // RFC 4226 §5.3 的動態截取
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            int modulo = (int) Math.pow(10, digits);
            return String.format(Locale.ROOT, "%0" + digits + "d", binary % modulo);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(algorithm + " is not available", ex);
        }
    }

    static String encode(byte[] data) {
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                result.append(BASE32.charAt((buffer >> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) {
            result.append(BASE32.charAt((buffer << (5 - bits)) & 0x1f));
        }
        return result.toString();
    }

    static byte[] decode(String base32) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : base32.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c == '=' || c == ' ') {
                continue;
            }
            int value = BASE32.indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("Not a Base32 secret");
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                result.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return result.toByteArray();
    }

    private static String encodeUri(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
