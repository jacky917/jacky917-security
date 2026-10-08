package jacky917.security.authorizationserver.token;

import java.util.Set;

/**
 * The roles and permissions written to an access token, without prefixes.
 * <p>
 * 寫入 Access Token 的角色與權限，皆不含前綴。
 *
 * @param roles        role codes; empty for third-party clients
 *                     <br>角色代碼；第三方 client 為空
 * @param permissions  permission codes
 *                     <br>權限代碼
 * @author Jacky
 * @since 2.1.0
 */
public record ResolvedAuthorities(Set<String> roles, Set<String> permissions) {
}
