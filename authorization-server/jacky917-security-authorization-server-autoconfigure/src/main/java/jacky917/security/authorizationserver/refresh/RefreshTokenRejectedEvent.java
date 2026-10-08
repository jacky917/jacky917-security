package jacky917.security.authorizationserver.refresh;

import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * Published when a refresh is refused, after its transaction has ended.
 * <p>
 * 刷新被拒絕時，在其交易結束後發布。
 *
 * @param reason              why it was refused
 *                            <br>拒絕原因
 * @param registeredClientId  the {@code oauth2_registered_client.id}, or
 *                            {@code null} for an unknown token
 *                            <br>{@code oauth2_registered_client.id}；不明的
 *                            token 為 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record RefreshTokenRejectedEvent(Reason reason, @Nullable String registeredClientId) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     *
     * @throws IllegalArgumentException if the client is missing for a
     *         reason other than {@link Reason#UNKNOWN_TOKEN}
     *         <br>若 {@code UNKNOWN_TOKEN} 以外的原因缺少 client
     */
    public RefreshTokenRejectedEvent {
        Objects.requireNonNull(reason, "reason");
        if (registeredClientId == null && reason != Reason.UNKNOWN_TOKEN) {
            throw new IllegalArgumentException("A " + reason + " refusal needs its client");
        }
    }

    /**
     * Why a refresh was refused.
     * <p>
     * 刷新被拒絕的原因。
     */
    public enum Reason {

        /**
         * The token was never issued, rotated longer ago than the history
         * keeps, or belongs to a login session that was revoked or expired
         * by the cleanup, whose authorizations are deleted. A refresh token
         * presented after logout is therefore counted here, not as
         * {@link #SESSION_NOT_ACTIVE}.
         * <p>
         * token 從未簽發、已輪換超過保留期間，或屬於已撤銷或已由清理排程判定過期
         * 的登入 Session（其授權已刪除）。因此登出後再出現的 Refresh Token 計入
         * 此原因，而不是 {@code SESSION_NOT_ACTIVE}。
         */
        UNKNOWN_TOKEN,

        /**
         * A rotated token within the grace period: usually two concurrent
         * refreshes.
         * <p>
         * 寬限期內的已輪換 token，通常是兩個併發的刷新。
         */
        CONCURRENT,

        /**
         * A rotated token after the grace period; the login session was
         * revoked.
         * <p>
         * 寬限期後的已輪換 token；登入 Session 已撤銷。
         */
        REUSE_DETECTED,

        /**
         * The authorization still exists but its login session cannot be
         * used: it expired and the cleanup has not run yet, or the
         * authorization has no login session.
         * <p>
         * 授權仍存在，但其登入 Session 無法使用：已過期但清理排程尚未執行，或
         * 授權沒有登入 Session。
         */
        SESSION_NOT_ACTIVE,

        /**
         * The user is no longer active, or the password changed after the
         * login; the login session was revoked.
         * <p>
         * 使用者已失效，或密碼在登入之後變更；登入 Session 已撤銷。
         */
        USER_NOT_ACTIVE
    }
}
