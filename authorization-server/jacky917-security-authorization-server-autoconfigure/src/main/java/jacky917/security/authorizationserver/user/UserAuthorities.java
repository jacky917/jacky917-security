package jacky917.security.authorizationserver.user;

import jacky917.security.core.Jacky917AuthorityPrefix;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;
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

    /**
     * Returns the authorities used by the authorization server's own pages:
     * {@code ROLE_<role>} and {@code PERM_<permission>}.
     * <p>
     * 回傳 Authorization Server 自身頁面使用的 authority：{@code ROLE_<角色>}
     * 與 {@code PERM_<權限>}。
     *
     * @return the granted authorities
     *         <br>授予的 authority
     */
    public List<GrantedAuthority> toGrantedAuthorities() {
        List<GrantedAuthority> granted = new ArrayList<>();
        roles.forEach(role -> granted.add(new SimpleGrantedAuthority(Jacky917AuthorityPrefix.ROLE + role)));
        permissions.forEach(permission ->
                granted.add(new SimpleGrantedAuthority(Jacky917AuthorityPrefix.PERMISSION + permission)));
        return granted;
    }
}
