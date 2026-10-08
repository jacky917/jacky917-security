package jacky917.security.authorizationserver.user;

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
     * Longest accepted password; longer input is rejected so hashing
     * cannot be abused.
     * <p>
     * 可接受的最長密碼；更長的輸入一律拒絕，避免雜湊被濫用。BCrypt 只使用前
     * 72 bytes，因此也不會讓過長的密碼產生誤導的安全感。
     */
    public static final int MAX_LENGTH = 128;

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
        if (length > MAX_LENGTH) {
            throw new IllegalArgumentException("The password must have at most " + MAX_LENGTH + " characters");
        }
        if (rawPassword.isBlank()) {
            throw new IllegalArgumentException("The password must not be blank");
        }
    }
}
