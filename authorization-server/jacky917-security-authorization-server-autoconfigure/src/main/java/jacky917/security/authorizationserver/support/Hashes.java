package jacky917.security.authorizationserver.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashes for one-time secrets stored in the database, so only the browser or
 * the client ever holds the secret itself.
 * <p>
 * 存入資料庫之一次性秘密值的雜湊，讓秘密值本身只存在於瀏覽器或 client 手中。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class Hashes {

    private Hashes() {
    }

    /**
     * Returns the SHA-256 of a value as 64 lowercase hex characters.
     * <p>
     * 以 64 個小寫十六進位字元回傳值的 SHA-256。
     *
     * @param value  the value, encoded as UTF-8
     *               <br>值，以 UTF-8 編碼
     * @return the hash
     *         <br>雜湊值
     */
    public static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
