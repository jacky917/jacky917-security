package jacky917.security.authorizationserver.refresh;

import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A refresh token that has been replaced by a newer one, kept in
 * {@code refresh_token_history} to detect reuse (data model §7.4).
 * <p>
 * 已被新 token 取代的 Refresh Token，保存在 {@code refresh_token_history} 中
 * 用於偵測重用（資料模型 §7.4）。
 *
 * @param tokenHash           SHA-256 of the token, as lowercase hex; the
 *                            token itself is never stored
 *                            <br>token 的 SHA-256（小寫十六進位）；不儲存
 *                            token 本身
 * @param authorizationId     the authorization the token belonged to
 *                            <br>token 所屬的授權
 * @param sessionId           the login session, or {@code null}
 *                            <br>登入 Session，或 {@code null}
 * @param userId              the user, or {@code null}
 *                            <br>使用者，或 {@code null}
 * @param registeredClientId  the client
 *                            <br>client
 * @param issuedAt            when the token was issued
 *                            <br>token 的簽發時間
 * @param rotatedAt           when it was replaced
 *                            <br>被取代的時間
 * @param expiresAt           when this record may be deleted
 *                            <br>此紀錄可以刪除的時間
 * @author Jacky
 * @since 2.1.0
 */
public record RotatedRefreshToken(
        String tokenHash,
        String authorizationId,
        @Nullable String sessionId,
        @Nullable String userId,
        String registeredClientId,
        Instant issuedAt,
        Instant rotatedAt,
        Instant expiresAt) {

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");

    /**
     * Creates the record, checking that it holds a hash and not a token.
     * <p>
     * 建立紀錄，並檢查保存的是雜湊而不是 token 本身。
     *
     * @throws IllegalArgumentException if {@code tokenHash} is not 64
     *         lowercase hex characters
     *         <br>若 {@code tokenHash} 不是 64 個小寫十六進位字元
     */
    public RotatedRefreshToken {
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(registeredClientId, "registeredClientId");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(rotatedAt, "rotatedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (tokenHash == null || !SHA256_HEX.matcher(tokenHash).matches()) {
            throw new IllegalArgumentException("tokenHash must be a SHA-256 in lowercase hex");
        }
    }
}
