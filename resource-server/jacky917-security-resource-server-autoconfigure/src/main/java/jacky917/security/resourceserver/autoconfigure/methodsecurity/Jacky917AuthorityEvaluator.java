package jacky917.security.resourceserver.autoconfigure.methodsecurity;

import jacky917.security.resourceserver.autoconfigure.properties.Jacky917SecurityProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Authority checks used by the {@code @Require*} method security
 * annotations.
 * <p>
 * 提供 {@code @Require*} 方法級授權註解使用的 authority 判斷工具。
 * <p>
 * {@code hasRole}, {@code hasPerm}, and {@code hasScope} add the prefixes
 * configured in {@code jacky917.security.jwt.prefix.*}, so the annotations
 * keep working when the prefixes change. {@code hasAnyAuthority} and
 * {@code hasAllAuthorities} take full authority names.
 * <p>
 * {@code hasRole}、{@code hasPerm}、{@code hasScope} 會加上
 * {@code jacky917.security.jwt.prefix.*} 設定的前綴，因此修改前綴後註解仍可
 * 正常運作。{@code hasAnyAuthority} 與 {@code hasAllAuthorities} 則使用完整
 * authority 名稱。
 * <p>
 * Every method fails closed: it returns {@code false} when the
 * authentication is {@code null} or when no non-blank value is given.
 * Instances are thread-safe.
 * <p>
 * 所有方法皆採「預設拒絕」：驗證資訊為 {@code null}，或沒有提供任何非空白的值時，
 * 一律回傳 {@code false}。實例為執行緒安全。
 *
 * @since 0.0.1
 */
public class Jacky917AuthorityEvaluator {

    private final Jacky917SecurityProperties.Jwt.Prefix prefix;

    /**
     * Creates an evaluator that uses the default prefixes
     * ({@code ROLE_}, {@code PERM_}, {@code SCOPE_}).
     * <p>
     * 建立使用預設前綴（{@code ROLE_}、{@code PERM_}、{@code SCOPE_}）的判斷工具。
     */
    public Jacky917AuthorityEvaluator() {
        this(new Jacky917SecurityProperties());
    }

    /**
     * Creates an evaluator that uses the prefixes from the given properties.
     * <p>
     * 建立使用指定設定中前綴的判斷工具。
     *
     * @param properties  the starter properties; must not be {@code null}
     *                    <br>starter 的設定屬性，不可為 {@code null}
     * @since 2.0.0
     */
    public Jacky917AuthorityEvaluator(Jacky917SecurityProperties properties) {
        this.prefix = properties.getJwt().getPrefix();
    }

    /**
     * Returns whether the authentication holds the given role, adding the
     * configured role prefix.
     * <p>
     * 回傳驗證資訊是否具備指定角色，會加上設定的角色前綴。
     *
     * @param authentication  the current authentication; may be {@code null}
     *                        <br>目前的驗證資訊，可為 {@code null}
     * @param role            the role without prefix, for example
     *                        {@code ADMIN}
     *                        <br>不含前綴的角色，例如 {@code ADMIN}
     * @return {@code true} if the role is held; {@code false} otherwise or
     *         when {@code role} is blank
     *         <br>具備該角色時為 {@code true}；否則或 {@code role} 為空白時為
     *         {@code false}
     * @since 2.0.0
     */
    public boolean hasRole(Authentication authentication, String role) {
        return hasPrefixed(authentication, prefix.getRole(), role);
    }

    /**
     * Returns whether the authentication holds the given permission, adding
     * the configured permission prefix.
     * <p>
     * 回傳驗證資訊是否具備指定權限，會加上設定的權限前綴。
     *
     * @param authentication  the current authentication; may be {@code null}
     *                        <br>目前的驗證資訊，可為 {@code null}
     * @param permission      the permission without prefix, for example
     *                        {@code order:read}
     *                        <br>不含前綴的權限，例如 {@code order:read}
     * @return {@code true} if the permission is held; {@code false} otherwise
     *         or when {@code permission} is blank
     *         <br>具備該權限時為 {@code true}；否則或 {@code permission} 為空白
     *         時為 {@code false}
     * @since 2.0.0
     */
    public boolean hasPerm(Authentication authentication, String permission) {
        return hasPrefixed(authentication, prefix.getPermission(), permission);
    }

    /**
     * Returns whether the authentication holds the given scope, adding the
     * configured scope prefix.
     * <p>
     * 回傳驗證資訊是否具備指定 scope，會加上設定的 scope 前綴。
     *
     * @param authentication  the current authentication; may be {@code null}
     *                        <br>目前的驗證資訊，可為 {@code null}
     * @param scope           the scope without prefix, for example
     *                        {@code profile.read}
     *                        <br>不含前綴的 scope，例如 {@code profile.read}
     * @return {@code true} if the scope is held; {@code false} otherwise or
     *         when {@code scope} is blank
     *         <br>具備該 scope 時為 {@code true}；否則或 {@code scope} 為空白時為
     *         {@code false}
     * @since 2.0.0
     */
    public boolean hasScope(Authentication authentication, String scope) {
        return hasPrefixed(authentication, prefix.getScope(), scope);
    }

    /**
     * Returns whether the authentication holds at least one of the listed
     * authorities (logical OR).
     * <p>
     * 回傳驗證資訊是否至少具備其中一個列出的 authority（OR 條件）。
     *
     * @param authentication       the current authentication; may be
     *                             {@code null}
     *                             <br>目前的驗證資訊，可為 {@code null}
     * @param requiredAuthorities  full authority names separated by
     *                             {@code |}; blank entries are ignored
     *                             <br>以 {@code |} 分隔的完整 authority
     *                             名稱，空白項目會被忽略
     * @return {@code true} if any listed authority is held; {@code false} if
     *         none is held, {@code authentication} is {@code null}, or no
     *         non-blank authority is listed
     *         <br>具備任一列出的 authority 時為 {@code true}；全部不具備、
     *         {@code authentication} 為 {@code null}，或未列出任何非空白
     *         authority 時為 {@code false}
     */
    public boolean hasAnyAuthority(Authentication authentication, String requiredAuthorities) {
        List<String> required = parseRequiredAuthorities(requiredAuthorities);
        if (authentication == null || required.isEmpty()) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return required.stream().anyMatch(owned::contains);
    }

    /**
     * Returns whether the authentication holds every listed authority
     * (logical AND).
     * <p>
     * 回傳驗證資訊是否具備所有列出的 authority（AND 條件）。
     *
     * @param authentication       the current authentication; may be
     *                             {@code null}
     *                             <br>目前的驗證資訊，可為 {@code null}
     * @param requiredAuthorities  full authority names separated by
     *                             {@code |}; blank entries are ignored
     *                             <br>以 {@code |} 分隔的完整 authority
     *                             名稱，空白項目會被忽略
     * @return {@code true} if every listed authority is held; {@code false}
     *         if any is missing, {@code authentication} is {@code null}, or
     *         no non-blank authority is listed
     *         <br>具備所有列出的 authority 時為 {@code true}；缺少任一項、
     *         {@code authentication} 為 {@code null}，或未列出任何非空白
     *         authority 時為 {@code false}
     */
    public boolean hasAllAuthorities(Authentication authentication, String requiredAuthorities) {
        List<String> required = parseRequiredAuthorities(requiredAuthorities);
        // An empty list must not pass: allMatch() on an empty stream is true.
        if (authentication == null || required.isEmpty()) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return owned.containsAll(required);
    }

    private boolean hasPrefixed(Authentication authentication, String authorityPrefix, String value) {
        if (authentication == null || !StringUtils.hasText(value)) {
            return false;
        }
        String required = (authorityPrefix == null ? "" : authorityPrefix) + value.trim();
        return currentAuthorities(authentication).contains(required);
    }

    private Set<String> currentAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    private List<String> parseRequiredAuthorities(String requiredAuthorities) {
        if (!StringUtils.hasText(requiredAuthorities)) {
            return List.of();
        }
        return Stream.of(requiredAuthorities.split("\\|"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }
}
