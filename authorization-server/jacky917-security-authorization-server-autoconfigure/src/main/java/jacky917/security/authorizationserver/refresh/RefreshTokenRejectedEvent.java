package jacky917.security.authorizationserver.refresh;

import org.jspecify.annotations.Nullable;

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
     * Why a refresh was refused.
     * <p>
     * 刷新被拒絕的原因。
     */
    public enum Reason {

        /**
         * The token was never issued, or rotated longer ago than the
         * history keeps.
         * <p>
         * token 從未簽發，或已輪換超過保留期間。
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
         * The login session is no longer active.
         * <p>
         * 登入 Session 已失效。
         */
        SESSION_NOT_ACTIVE,

        /**
         * The user is no longer active, or changed the password.
         * <p>
         * 使用者已失效，或已變更密碼。
         */
        USER_NOT_ACTIVE
    }
}
