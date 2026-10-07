package jacky917.security.authorizationserver.federation;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Converts an identity provider's user into {@link FederatedUserInfo}. Add
 * a bean of this type to support a provider whose attributes differ from
 * OpenID Connect.
 * <p>
 * 將身分提供者的使用者轉換為 {@link FederatedUserInfo}。提供者的屬性與 OpenID
 * Connect 不同時，加入此型別的 bean 即可支援。
 *
 * @author Jacky
 * @since 2.1.0
 */
public interface FederatedUserInfoMapper {

    /**
     * Returns whether this mapper handles the given provider.
     * <p>
     * 回傳此 mapper 是否處理指定的提供者。
     *
     * @param registrationId  the registration id, for example {@code google}
     *                        <br>registration id，例如 {@code google}
     * @return {@code true} if supported
     *         <br>支援時為 {@code true}
     */
    boolean supports(String registrationId);

    /**
     * Converts the provider's user.
     * <p>
     * 轉換提供者的使用者。
     *
     * @param registrationId  the registration id
     *                        <br>registration id
     * @param user            the user returned by the provider
     *                        <br>提供者回傳的使用者
     * @param accessToken     the provider's access token, used only to
     *                        fetch extra data and never stored
     *                        <br>提供者的 access token，只用於取得額外資料，
     *                        不會儲存
     * @return the user in the common shape
     *         <br>統一格式的使用者資料
     */
    FederatedUserInfo map(String registrationId, OAuth2User user, OAuth2AccessToken accessToken);
}
