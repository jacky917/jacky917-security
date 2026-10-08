package jacky917.security.authorizationserver.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashes of secrets that are looked up in the database, so the table that
 * finds them stores the hash instead of the secret.
 * <p>
 * 在資料庫中查詢之秘密值的雜湊，讓用於查詢的表只存雜湊而不存秘密值本身。
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
