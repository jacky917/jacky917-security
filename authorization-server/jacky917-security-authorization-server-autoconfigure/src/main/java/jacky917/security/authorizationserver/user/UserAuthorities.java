package jacky917.security.authorizationserver.user;

import java.util.Set;

/**
 * A user's current roles and permissions, without prefixes.
 * <p>
 * 使用者目前的角色與權限，皆不含前綴。
 *
 * @param roles        role codes, for example {@code USER}
 *                     <br>角色代碼，例如 {@code USER}
 * @param permissions  permission codes, for example {@code as:user:read}
 *                     <br>權限代碼，例如 {@code as:user:read}
 * @author Jacky
 * @since 2.1.0
 */
public record UserAuthorities(Set<String> roles, Set<String> permissions) {
}
