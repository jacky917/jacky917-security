package jacky917.security.authorizationserver.user;

import java.time.Duration;
import java.util.Objects;

/**
 * When too many failed password logins lock an account (detailed design
 * §5.1).
 * <p>
 * 連續密碼登入失敗多少次時鎖定帳號（詳細設計 §5.1）。
 *
 * @param maxFailures   consecutive failures that lock the account; at least 1
 *                      <br>鎖定帳號的連續失敗次數，至少為 1
 * @param lockDuration  how long the account stays locked; positive
 *                      <br>鎖定的時間，必須為正值
 * @author Jacky
 * @since 2.1.0
 */
public record LockoutPolicy(int maxFailures, Duration lockDuration) {

    /**
     * Creates a policy.
     * <p>
     * 建立政策。
     *
     * @throws IllegalArgumentException if {@code maxFailures} is less than 1
     *         or {@code lockDuration} is not positive
     *         <br>若 {@code maxFailures} 小於 1，或 {@code lockDuration} 不是正值
     */
    public LockoutPolicy {
        Objects.requireNonNull(lockDuration, "lockDuration");
        if (maxFailures < 1) {
            throw new IllegalArgumentException("maxFailures must be at least 1: " + maxFailures);
        }
        if (lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("lockDuration must be positive: " + lockDuration);
        }
    }
}
