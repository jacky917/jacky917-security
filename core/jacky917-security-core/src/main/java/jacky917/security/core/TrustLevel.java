package jacky917.security.core;

/**
 * How much the authorization server trusts an OAuth client.
 * <p>
 * Authorization Server 對 OAuth client 的信任等級。
 * <p>
 * The trust level decides what an access token may contain: first-party
 * clients receive the user's roles and permissions, third-party clients only
 * the permissions covered by the scopes the user consented to.
 * <p>
 * 信任等級決定 Access Token 可以包含的內容：第一方 client 取得使用者的角色與
 * 權限；第三方 client 只取得使用者同意的 scope 所涵蓋的權限。
 *
 * @since 2.0.0
 */
public enum TrustLevel {

    /**
     * A client operated by the same organization, such as its own BFF.
     * <p>
     * 由同一組織營運的 client，例如自家的 BFF。
     */
    FIRST_PARTY,

    /**
     * A client operated by another party; requires user consent.
     * <p>
     * 由其他單位營運的 client，需要使用者同意。
     */
    THIRD_PARTY
}
