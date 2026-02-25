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
 * 從 JWT Claims 中提取權限資訊的核心轉換器。
 * <p>
 * 支援從多個 claims (roles, permissions, scope, scp) 中提取權限，
 * 並可透過設定檔自訂 claim 名稱與權限前綴。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final Jacky917SecurityProperties properties;

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

        return getAuthoritiesFromClaim(claimValue, prefix, delimiter);
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
