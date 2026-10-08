package jacky917.security.authorizationserver.user;

import java.nio.charset.StandardCharsets;

/**
 * Password rules (D21, following NIST SP 800-63B): length matters, no
 * composition rules.
 * <p>
 * 密碼規則（D21，依 NIST SP 800-63B）：重視長度，不強制字元組合。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PasswordPolicy {

    /**
     * Longest accepted password, in UTF-8 bytes: about 72 letters or
     * digits, or 24 Chinese characters. BCrypt uses at most 72 bytes, and
     * Spring Security refuses to hash a longer password, so a longer one
     * must be refused here, before a reset link or a registration is used.
     * <p>
     * 可接受的最長密碼，以 UTF-8 的 byte 計算：約 72 個英數字或 24 個中文字。
     * BCrypt 最多只使用 72 bytes，Spring Security 也拒絕雜湊更長的密碼，因此
     * 必須在這裡先拒絕，不能等到使用重設連結或註冊之後才失敗。
     */
    public static final int MAX_BYTES = 72;

    private final int minLength;

    /**
     * Creates a policy.
     * <p>
     * 建立密碼政策。
     *
     * @param minLength  the minimum number of characters
     *                   <br>最少字元數
     */
    public PasswordPolicy(int minLength) {
        this.minLength = minLength;
    }

    /**
     * Returns the minimum number of characters.
     * <p>
     * 回傳最少字元數。
     *
     * @return the minimum length
     *         <br>最少字元數
     */
    public int minLength() {
        return minLength;
    }

    /**
     * Checks a new password.
     * <p>
     * 檢查新密碼。
     *
     * @param rawPassword  the password to check
     *                     <br>要檢查的密碼
     * @throws IllegalArgumentException if the password breaks a rule
     *         <br>密碼不符合規則時
     */
    public void check(String rawPassword) {
        int length = rawPassword.codePointCount(0, rawPassword.length());
        if (length < minLength) {
            throw new IllegalArgumentException("The password must have at least " + minLength + " characters");
        }
        if (rawPassword.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new IllegalArgumentException("The password must have at most " + MAX_BYTES + " bytes in UTF-8");
        }
        if (rawPassword.isBlank()) {
            throw new IllegalArgumentException("The password must not be blank");
        }
    }
}
