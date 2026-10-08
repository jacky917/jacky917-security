package jacky917.security.authorizationserver.client;

import jacky917.security.core.TrustLevel;

/**
 * The jacky917 data kept for a registered client in {@code client_profile}.
 * <p>
 * 存放在 {@code client_profile} 中、屬於某個已註冊 client 的 jacky917 資料。
 *
 * @param registeredClientId  the {@code oauth2_registered_client.id}
 *                            <br>對應的 {@code oauth2_registered_client.id}
 * @param trustLevel          how much the client is trusted
 *                            <br>信任等級
 * @param displayName         the name shown to users
 *                            <br>顯示給使用者的名稱
 * @param status              whether the client can obtain tokens
 *                            <br>是否可以取得 token
 * @author Jacky
 * @since 2.1.0
 */
public record ClientProfile(String registeredClientId, TrustLevel trustLevel, String displayName, ClientStatus status) {
}
