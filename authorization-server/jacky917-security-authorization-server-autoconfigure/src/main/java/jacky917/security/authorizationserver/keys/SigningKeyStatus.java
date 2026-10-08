package jacky917.security.authorizationserver.keys;

/**
 * Lifecycle of a signing key (data model §10.3).
 * <p>
 * 簽章金鑰的生命週期（資料模型 §10.3）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum SigningKeyStatus {

    /**
     * Published in the JWKS ahead of use, so resource servers cache it
     * before it signs anything.
     * <p>
     * 在開始使用前先公開於 JWKS，讓 Resource Server 在它簽發任何 token 前就已快取。
     */
    NEXT,

    /**
     * The single key that signs new tokens; also published.
     * <p>
     * 唯一用來簽發新 token 的金鑰，同時公開。
     */
    ACTIVE,

    /**
     * No longer signs, still published until the tokens it signed expire.
     * <p>
     * 不再簽章，但在它簽發的 token 過期前仍公開。
     */
    RETIRING,

    /**
     * Neither signs nor published.
     * <p>
     * 不再簽章，也不再公開。
     */
    RETIRED
}
