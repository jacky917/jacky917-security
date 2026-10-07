package jacky917.security.autoconfigure.authentication;

import jacky917.security.autoconfigure.properties.Jacky917SecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Converter that maps JWT claims to Spring Security granted authorities.
 * <p>
 * 將 JWT claims 轉換為 Spring Security granted authority 的核心轉換器。
 * <p>
 * Authorities are read from the roles, permissions, {@code scope}, and
 * {@code scp} claims. Claim names and authority prefixes come from
 * {@link Jacky917SecurityProperties}. Each claim may be a string or a
 * collection: role and permission strings are split on commas, and the
 * {@code scope} string is split on whitespace. Blank values are skipped,
 * and claims of any other type are ignored with a warning.
 * <p>
 * 權限來源為 roles、permissions、{@code scope} 與 {@code scp} 這幾個 claim，
 * claim 名稱與權限前綴由 {@code Jacky917SecurityProperties} 設定。每個 claim
 * 可以是字串或集合：roles 與 permissions 的字串以逗號分隔，{@code scope}
 * 字串以空白分隔。空白值會被略過，其他型別的 claim 則記錄警告後忽略。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final Jacky917SecurityProperties properties;

    /**
     * Extracts the granted authorities from the given JWT.
     * <p>
     * 從指定的 JWT 中提取 granted authority。
     *
     * @param jwt  the decoded JWT to read claims from
     *             <br>要讀取 claims 的已解碼 JWT
     * @return a mutable set of distinct authorities sorted by name; empty if
     *         no configured claim yields a value
     *         <br>依名稱排序、不重複且可修改的 authority 集合；若設定的
     *         claim 皆無值則為空集合
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new TreeSet<>(Comparator.comparing(GrantedAuthority::getAuthority));

        authorities.addAll(extractRoles(jwt));
        authorities.addAll(extractPermissions(jwt));

        // Scopes are special and need merging from two possible claims
        Set<GrantedAuthority> scopes = new HashSet<>();
        // Handle string-based scope (e.g., "openid profile")
        scopes.addAll(extractAuthorities(
                jwt,
                properties.getJwt().getClaims().getScope(),
                properties.getJwt().getPrefix().getScope(),
                "\\s+"
        ));
        // Handle array-based scp (e.g., ["read:data", "write:data"])
        scopes.addAll(extractAuthorities(
                jwt,
                properties.getJwt().getClaims().getScp(),
                properties.getJwt().getPrefix().getScope()
        ));
        authorities.addAll(scopes);

        if (properties.isDebugLog() && !authorities.isEmpty()) {
            log.debug("Extracted authorities: {}", authorities);
        }

        return authorities;
    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
        return extractAuthorities(
                jwt,
                properties.getJwt().getClaims().getRoles(),
                properties.getJwt().getPrefix().getRole()
        );
    }

    private Collection<GrantedAuthority> extractPermissions(Jwt jwt) {
        return extractAuthorities(
                jwt,
                properties.getJwt().getClaims().getPermissions(),
                properties.getJwt().getPrefix().getPermission()
        );
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt, String claimName, String prefix) {
        // Default delimiter is comma for list-like strings (e.g., permissions)
        return extractAuthorities(jwt, claimName, prefix, ",");
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt, String claimName, String prefix, String delimiter) {
        if (!StringUtils.hasText(claimName)) {
            return Collections.emptySet();
        }

        Object claimValue = jwt.getClaim(claimName);
        if (claimValue == null) {
            return Collections.emptySet();
        }

        // A null prefix (for example, an empty YAML value) must not become "null"
        String safePrefix = prefix == null ? "" : prefix;
        return getAuthoritiesFromClaim(claimValue, safePrefix, delimiter);
    }

    private Set<GrantedAuthority> getAuthoritiesFromClaim(Object claimValue, String prefix, String delimiter) {
        if (claimValue instanceof String claimStr) {
            if (!StringUtils.hasText(claimStr)) {
                return Collections.emptySet();
            }
            return Stream.of(claimStr.split(delimiter))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .map(s -> new SimpleGrantedAuthority(prefix + s))
                    .collect(Collectors.toSet());
        }

        if (claimValue instanceof Collection<?> claimColl) {
            return claimColl.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .map(s -> new SimpleGrantedAuthority(prefix + s))
                    .collect(Collectors.toSet());
        }

        if (log.isWarnEnabled()) {
            log.warn("Unsupported claim type for authority extraction: {}. Expected String or Collection.",
                    claimValue.getClass().getName());
        }

        return Collections.emptySet();
    }
}
