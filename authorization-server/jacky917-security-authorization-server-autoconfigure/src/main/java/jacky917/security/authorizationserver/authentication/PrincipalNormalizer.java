package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Turns any login into the same kind of {@link Authentication} (D16): a
 * {@link UsernamePasswordAuthenticationToken} whose principal is a Spring
 * {@link User} named after the user id.
 * <p>
 * 把任何登入方式都轉換為相同的 {@link Authentication}（D16）：principal 為以
 * 使用者 ID 命名之 Spring {@link User} 的 {@link UsernamePasswordAuthenticationToken}。
 * <p>
 * The token {@code sub} and the stored principal are then the user id for
 * every login method, and Spring Security can store the authorization
 * without custom serialization. Spring Security derives the ID token
 * {@code auth_time} from a factor authority and refuses to issue an ID
 * token without one, but its {@code oauth2Login} adds none (verified with
 * 7.1.1); the original factor authorities are therefore kept, and
 * {@code FACTOR_AUTHORIZATION_CODE} with the login time is added when
 * there is none.
 * <p>
 * 如此一來，不論登入方式，token 的 {@code sub} 與儲存的 principal 都是使用者
 * ID，Spring Security 也不需要自訂序列化即可儲存授權。Spring Security 以
 * factor authority 決定 ID Token 的 {@code auth_time}，沒有時拒絕簽發 ID
 * Token，但它的 {@code oauth2Login} 不會加入任何 factor authority（已以 7.1.1
 * 實測）；因此保留原本的 factor authority，沒有時加入帶登入時間的
 * {@code FACTOR_AUTHORIZATION_CODE}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PrincipalNormalizer {

    private final UserAccountService users;
    private final Clock clock;

    /**
     * Creates the normalizer.
     * <p>
     * 建立 normalizer。
     *
     * @param users  the user account service, for the authorities
     *               <br>使用者帳號服務，用於取得 authority
     * @param clock  the clock for the login time
     *               <br>用於登入時間的時鐘
     */
    public PrincipalNormalizer(UserAccountService users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    /**
     * Returns the standard authentication for a user.
     * <p>
     * 回傳使用者的標準 Authentication。
     *
     * @param userId    the user id
     *                  <br>使用者 ID
     * @param original  the authentication produced by the login
     *                  <br>登入產生的 Authentication
     * @return the standard authentication
     *         <br>標準的 Authentication
     */
    public Authentication normalize(String userId, Authentication original) {
        List<GrantedAuthority> authorities = new ArrayList<>(users.loadAuthorities(userId).toGrantedAuthorities());
        List<GrantedAuthority> factors = original.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance).map(GrantedAuthority.class::cast).toList();
        if (factors.isEmpty()) {
            authorities.add(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY)
                    .issuedAt(clock.instant()).build());
        } else {
            authorities.addAll(factors);
        }
        User principal = new User(userId, "", authorities);
        principal.eraseCredentials();
        UsernamePasswordAuthenticationToken normalized =
                UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities);
        normalized.setDetails(original.getDetails());
        return normalized;
    }
}
