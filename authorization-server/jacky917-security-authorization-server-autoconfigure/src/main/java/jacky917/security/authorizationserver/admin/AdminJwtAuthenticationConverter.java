package jacky917.security.authorizationserver.admin;

import jacky917.security.core.Jacky917ClaimNames;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

/**
 * Reads the administration permissions of an access token (phase 3 and 4
 * design D23).
 * <p>
 * 讀取 Access Token 中的管理權限（第 3、4 階段設計 D23）。
 * <ul>
 *   <li>A user's token (with an {@code asid}) has them in its
 *       {@code permissions} claim, from the user's roles.
 *       <br>使用者的 token（有 {@code asid}）的權限在 {@code permissions}
 *       claim 中，來自使用者的角色。</li>
 *   <li>A {@code client_credentials} token has them as scopes the client was
 *       given.
 *       <br>{@code client_credentials} 的 token 的權限是 client 被授予的
 *       scope。</li>
 * </ul>
 * Only values starting with {@code as:} become authorities, without any
 * prefix, for example {@code as:user:read}.
 * <p>
 * 只有以 {@code as:} 開頭的值會成為 authority，且不加前綴，例如
 * {@code as:user:read}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AdminJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    /**
     * The prefix of the authorization server's own permissions.
     * <p>
     * Authorization Server 自身權限的前綴。
     */
    public static final String ADMIN_PERMISSION_PREFIX = "as:";

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Stream<String> values = jwt.hasClaim(Jacky917ClaimNames.ASID)
                ? values(jwt.getClaim(Jacky917ClaimNames.PERMISSIONS))
                : values(jwt.getClaim(Jacky917ClaimNames.SCOPE));
        List<GrantedAuthority> authorities = values.filter(value -> value.startsWith(ADMIN_PERMISSION_PREFIX))
                .distinct().map(value -> (GrantedAuthority) new SimpleGrantedAuthority(value)).toList();
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    private static Stream<String> values(Object claim) {
        if (claim instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf);
        }
        if (claim instanceof String text) {
            return Arrays.stream(text.trim().split("\\s+")).filter(value -> !value.isEmpty());
        }
        return Stream.empty();
    }
}
