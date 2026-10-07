package jacky917.security.authorizationserver.client;

/**
 * Status of a client (data model §10.4).
 * <p>
 * Client 的狀態（資料模型 §10.4）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum ClientStatus {

    /**
     * Registered but not yet approved; cannot obtain tokens.
     * <p>
     * 已註冊、尚未核准，無法取得 token。
     */
    PENDING_REVIEW,

    /**
     * Can obtain tokens.
     * <p>
     * 可以取得 token。
     */
    ACTIVE,

    /**
     * Suspended; cannot obtain tokens.
     * <p>
     * 已停權，無法取得 token。
     */
    SUSPENDED
}
