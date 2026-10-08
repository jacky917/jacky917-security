package jacky917.security.authorizationserver.mfa;

import jacky917.security.authorizationserver.keys.KeyEncryptor;
import jacky917.security.authorizationserver.user.UserAccountService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Two-step verification with an authenticator app (phase 3 and 4 design
 * §7, D31).
 * <p>
 * 以驗證器 App 進行兩步驟驗證（第 3、4 階段設計 §7、D31）。
 * <ul>
 *   <li>The secret is stored encrypted with the master key
 *       ({@code keys.encryption-key}).
 *       <br>密鑰以主金鑰（{@code keys.encryption-key}）加密儲存。</li>
 *   <li>A code is accepted for the current 30-second step or the one
 *       before or after it, and only once.
 *       <br>驗證碼在目前、前一個或後一個 30 秒時間步內有效，且只能使用一次。</li>
 *   <li>Enabling creates 10 single-use recovery codes; only their SHA-256
 *       hashes are stored.
 *       <br>啟用時產生 10 組一次性復原碼，只儲存其 SHA-256 雜湊。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class MfaService {

    /**
     * How many recovery codes are created.
     * <p>
     * 產生的復原碼數量。
     */
    public static final int RECOVERY_CODES = 10;

    private static final String RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcClient jdbc;
    private final UserAccountService users;
    private final KeyEncryptor encryptor;
    private final Set<String> requiredRoles;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc           the JDBC client of the authorization server
     *                       database
     *                       <br>Authorization Server 資料庫的 JDBC client
     * @param users          reads the roles of a user
     *                       <br>讀取使用者的角色
     * @param encryptor      encrypts the secrets with the master key
     *                       <br>以主金鑰加密密鑰
     * @param requiredRoles  the roles that must use two-step verification
     *                       <br>必須使用兩步驟驗證的角色
     * @param transactions   changes the secret and the recovery codes
     *                       together
     *                       <br>在同一個交易中變更密鑰與復原碼
     * @param clock          the clock
     *                       <br>時鐘
     */
    public MfaService(JdbcClient jdbc, UserAccountService users, KeyEncryptor encryptor, Set<String> requiredRoles,
                      TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.encryptor = encryptor;
        this.requiredRoles = Set.copyOf(requiredRoles);
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Returns whether a user turned two-step verification on.
     * <p>
     * 回傳使用者是否已啟用兩步驟驗證。
     *
     * @param userId  the user
     *                <br>使用者
     * @return {@code true} if it is on
     *         <br>已啟用時為 {@code true}
     */
    public boolean isEnabled(String userId) {
        return jdbc.sql("SELECT COUNT(*) FROM user_mfa_totp WHERE user_id = :user").param("user", userId)
                .query(Integer.class).single() > 0;
    }

    /**
     * Returns whether a user has a role that must use two-step
     * verification ({@code mfa.required-roles}).
     * <p>
     * 回傳使用者是否擁有必須使用兩步驟驗證的角色（{@code mfa.required-roles}）。
     *
     * @param userId  the user
     *                <br>使用者
     * @return {@code true} if two-step verification is required
     *         <br>必須使用兩步驟驗證時為 {@code true}
     */
    public boolean isRequired(String userId) {
        return !requiredRoles.isEmpty()
                && users.loadAuthorities(userId).roles().stream().anyMatch(requiredRoles::contains);
    }

    /**
     * Returns the state of a user's two-step verification.
     * <p>
     * 回傳使用者的兩步驟驗證狀態。
     *
     * @param userId  the user
     *                <br>使用者
     * @return the state, or empty if it is off
     *         <br>狀態；未啟用時為空
     */
    public Optional<Status> status(String userId) {
        return jdbc.sql("SELECT enabled_at FROM user_mfa_totp WHERE user_id = :user").param("user", userId)
                .query(Timestamp.class).optional()
                .map(enabledAt -> new Status(enabledAt.toInstant(), remainingRecoveryCodes(userId)));
    }

    /**
     * Turns two-step verification on with a new secret, if the code proves
     * that the authenticator app has it.
     * <p>
     * 以新的密鑰啟用兩步驟驗證；驗證碼必須證明驗證器 App 已有此密鑰。
     *
     * @param userId  the user
     *                <br>使用者
     * @param secret  the Base32 secret shown to the user
     *                <br>顯示給使用者的 Base32 密鑰
     * @param code    the code from the app
     *                <br>App 上的驗證碼
     * @return the recovery codes, shown only now; empty if the code is wrong
     *         or two-step verification is already on
     *         <br>復原碼，只在此時顯示；驗證碼錯誤或已啟用時為空
     */
    public Optional<List<String>> enable(String userId, String secret, String code) {
        Instant now = clock.instant();
        OptionalLong step = Totp.verify(secret, code, now, 0);
        if (step.isEmpty()) {
            return Optional.empty();
        }
        return transactions.execute(status -> {
            if (isEnabled(userId)) {
                return Optional.<List<String>>empty();
            }
            jdbc.sql("INSERT INTO user_mfa_totp (user_id, secret_encrypted, encryption_key_id, last_used_step, "
                            + "enabled_at) VALUES (:user, :secret, :key, :step, :now)")
                    .param("user", userId).param("secret", encryptor.encrypt(secret, keyName(userId)))
                    .param("key", encryptor.masterKeyId()).param("step", step.getAsLong())
                    .param("now", Timestamp.from(now)).update();
            log.info("User {} turned on two-step verification", userId);
            return Optional.of(replaceRecoveryCodes(userId, now));
        });
    }

    /**
     * Checks a code from the authenticator app or a recovery code. A code
     * is used up when it is accepted.
     * <p>
     * 檢查驗證器 App 的驗證碼或復原碼。驗證碼被接受後即用掉。
     *
     * @param userId  the user
     *                <br>使用者
     * @param code    a 6-digit code or a recovery code
     *                <br>6 位數的驗證碼或復原碼
     * @return how the code was accepted, or {@link Verification#INVALID}
     *         <br>驗證碼被接受的方式，或 {@code INVALID}
     */
    public Verification verify(String userId, String code) {
        String typed = code.strip();
        if (typed.isEmpty()) {
            return Verification.INVALID;
        }
        Verification result = transactions.execute(status -> {
            if (typed.replace(" ", "").chars().allMatch(Character::isDigit)) {
                return verifyTotp(userId, typed) ? Verification.TOTP : Verification.INVALID;
            }
            int used = jdbc.sql("UPDATE user_recovery_code SET used_at = :now WHERE user_id = :user "
                            + "AND code_hash = :hash AND used_at IS NULL")
                    .param("now", Timestamp.from(clock.instant())).param("user", userId)
                    .param("hash", sha256(normalizeRecoveryCode(typed))).update();
            return used == 1 ? Verification.RECOVERY_CODE : Verification.INVALID;
        });
        return result == null ? Verification.INVALID : result;
    }

    /**
     * Replaces the recovery codes, after checking a code from the
     * authenticator app.
     * <p>
     * 檢查驗證器 App 的驗證碼後，取代復原碼。
     *
     * @param userId  the user
     *                <br>使用者
     * @param code    the code from the app
     *                <br>App 上的驗證碼
     * @return the new recovery codes, shown only now; empty if the code is
     *         wrong
     *         <br>新的復原碼，只在此時顯示；驗證碼錯誤時為空
     */
    public Optional<List<String>> regenerateRecoveryCodes(String userId, String code) {
        return transactions.execute(status -> verifyTotp(userId, code.strip())
                ? Optional.of(replaceRecoveryCodes(userId, clock.instant()))
                : Optional.<List<String>>empty());
    }

    /**
     * Turns two-step verification off and deletes the recovery codes.
     * <p>
     * 停用兩步驟驗證並刪除復原碼。
     *
     * @param userId  the user
     *                <br>使用者
     * @return {@code true} if it was on
     *         <br>原本已啟用時為 {@code true}
     */
    public boolean disable(String userId) {
        Boolean disabled = transactions.execute(status -> {
            jdbc.sql("DELETE FROM user_recovery_code WHERE user_id = :user").param("user", userId).update();
            return jdbc.sql("DELETE FROM user_mfa_totp WHERE user_id = :user").param("user", userId).update() > 0;
        });
        if (Boolean.TRUE.equals(disabled)) {
            log.info("Two-step verification of user {} turned off", userId);
        }
        return Boolean.TRUE.equals(disabled);
    }

    private boolean verifyTotp(String userId, String code) {
        Optional<Secret> secret = jdbc.sql("SELECT secret_encrypted, encryption_key_id, last_used_step "
                        + "FROM user_mfa_totp WHERE user_id = :user")
                .param("user", userId)
                .query((rs, rowNum) -> new Secret(rs.getString(1), rs.getString(2), rs.getLong(3))).optional();
        if (secret.isEmpty()) {
            return false;
        }
        String plain = encryptor.decrypt(secret.get().encrypted(), keyName(userId), secret.get().keyId());
        OptionalLong step = Totp.verify(plain, code, clock.instant(), secret.get().lastUsedStep());
        if (step.isEmpty()) {
            return false;
        }
        // 只在時間步比上一次大時更新：同時送出的同一個驗證碼只有一個成功
        return jdbc.sql("UPDATE user_mfa_totp SET last_used_step = :step WHERE user_id = :user "
                        + "AND last_used_step < :step")
                .param("step", step.getAsLong()).param("user", userId).update() == 1;
    }

    private List<String> replaceRecoveryCodes(String userId, Instant now) {
        jdbc.sql("DELETE FROM user_recovery_code WHERE user_id = :user").param("user", userId).update();
        List<String> codes = new ArrayList<>();
        while (codes.size() < RECOVERY_CODES) {
            String code = newRecoveryCode();
            if (!codes.contains(code)) {
                codes.add(code);
                jdbc.sql("INSERT INTO user_recovery_code (user_id, code_hash, created_at) VALUES (:user, :hash, :now)")
                        .param("user", userId).param("hash", sha256(normalizeRecoveryCode(code)))
                        .param("now", Timestamp.from(now)).update();
            }
        }
        return codes;
    }

    private int remainingRecoveryCodes(String userId) {
        return jdbc.sql("SELECT COUNT(*) FROM user_recovery_code WHERE user_id = :user AND used_at IS NULL")
                .param("user", userId).query(Integer.class).single();
    }

    private static String newRecoveryCode() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            if (i == 5) {
                code.append('-');
            }
            code.append(RECOVERY_ALPHABET.charAt(RANDOM.nextInt(RECOVERY_ALPHABET.length())));
        }
        return code.toString();
    }

    private static String normalizeRecoveryCode(String code) {
        return code.replace("-", "").replace(" ", "").toLowerCase(Locale.ROOT);
    }

    private static String keyName(String userId) {
        // 加密時的附加資料：密鑰只能以同一位使用者解密
        return "totp:" + userId;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private record Secret(String encrypted, String keyId, long lastUsedStep) {
    }

    /**
     * How a code was accepted.
     * <p>
     * 驗證碼被接受的方式。
     */
    public enum Verification {

        /**
         * A code from the authenticator app.
         * <p>
         * 驗證器 App 的驗證碼。
         */
        TOTP,

        /**
         * A recovery code, now used up.
         * <p>
         * 復原碼，已用掉。
         */
        RECOVERY_CODE,

        /**
         * The code is wrong or was already used.
         * <p>
         * 驗證碼錯誤或已使用過。
         */
        INVALID
    }

    /**
     * The state of a user's two-step verification.
     * <p>
     * 使用者的兩步驟驗證狀態。
     *
     * @param enabledAt               when it was turned on
     *                                <br>啟用時間
     * @param remainingRecoveryCodes  how many recovery codes are left
     *                                <br>剩餘的復原碼數量
     */
    public record Status(Instant enabledAt, int remainingRecoveryCodes) {
    }
}
