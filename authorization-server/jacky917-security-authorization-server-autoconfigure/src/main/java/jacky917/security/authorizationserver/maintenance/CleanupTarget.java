package jacky917.security.authorizationserver.maintenance;

import java.util.Locale;

/**
 * The kinds of expired data that {@link DataCleanup} removes (data model
 * §14.1).
 * <p>
 * {@code DataCleanup} 移除的過期資料種類（資料模型 §14.1）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum CleanupTarget {

    /**
     * Authorizations whose tokens have all expired, and abandoned ones.
     * <p>
     * 所有 token 皆已過期的授權，以及被放棄的授權。
     */
    AUTHORIZATIONS,

    /**
     * Rotated refresh tokens past their retention.
     * <p>
     * 超過保留期間的已輪換 Refresh Token。
     */
    REFRESH_TOKEN_HISTORY,

    /**
     * Active login sessions past their absolute lifetime, marked
     * {@code EXPIRED} rather than deleted.
     * <p>
     * 超過絕對有效期的有效登入 Session；改為 {@code EXPIRED}，而不是刪除。
     */
    EXPIRED_SESSIONS,

    /**
     * Revoked and expired login sessions older than 30 days.
     * <p>
     * 已撤銷或已過期超過 30 天的登入 Session。
     */
    SESSIONS,

    /**
     * Action tokens that expired more than 7 days ago.
     * <p>
     * 到期超過 7 天的操作 token。
     */
    ACTION_TOKENS,

    /**
     * Login and admin audit rows past their retention.
     * <p>
     * 超過保留期間的登入稽核與管理稽核紀錄。
     */
    AUDITS,

    /**
     * Signing keys retired more than a year ago.
     * <p>
     * 退役超過一年的簽章金鑰。
     */
    SIGNING_KEYS;

    /**
     * Returns the name used in logs and as the metric tag value.
     * <p>
     * 回傳用於日誌與 metric tag 值的名稱。
     *
     * @return the lower-case name, for example {@code expired_sessions}
     *         <br>小寫名稱，例如 {@code expired_sessions}
     */
    public String tag() {
        return name().toLowerCase(Locale.ROOT);
    }
}
