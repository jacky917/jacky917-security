package jacky917.security.authorizationserver.user;

import jacky917.security.core.Jacky917AuthorityPrefix;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads users for password login. The login name can be the username or
 * a verified email.
 * <p>
 * 為帳號密碼登入載入使用者。登入帳號可以是帳號或已驗證的 Email。
 * <p>
 * The returned {@code UserDetails} uses the user id as its username (D16),
 * so after login {@code Authentication#getName()} and the token {@code sub}
 * are the user id, whichever name was typed. Every failure reason (unknown
 * user, no password, deleted) throws the same exception, so the login page
 * cannot reveal whether an account exists.
 * <p>
 * 回傳的 {@code UserDetails} 以使用者 ID 作為 username（D16），因此不論輸入的
 * 是帳號還是 Email，登入後的 {@code Authentication#getName()} 與 token 的
 * {@code sub} 都是使用者 ID。所有失敗原因（帳號不存在、沒有密碼、已刪除）都
 * 丟出相同的例外，登入頁因此無法透露帳號是否存在。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class Jacky917UserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserAccountService users;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param users  the user account service
     *               <br>使用者帳號服務
     * @param clock  the clock used for temporary locks
     *               <br>判斷暫時鎖定所用的時鐘
     */
    public Jacky917UserDetailsService(UserAccountService users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Override
    public UserDetails loadUserByUsername(String login) {
        UserAccount user = users.findByLogin(login)
                .filter(account -> account.status() != UserStatus.DELETED && account.passwordHash() != null)
                .orElseThrow(() -> new UsernameNotFoundException("Bad credentials"));
        return toUserDetails(user, user.passwordHash());
    }

    /**
     * Stores a re-hashed password after a successful login with outdated
     * hashing parameters (D21).
     * <p>
     * 以過時的雜湊參數登入成功後，儲存重新雜湊的密碼（D21）。
     */
    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        users.updatePasswordHash(user.getUsername(), newPassword);
        return User.withUserDetails(user).password(newPassword).build();
    }

    private UserDetails toUserDetails(UserAccount user, String passwordHash) {
        Instant now = clock.instant();
        UserAuthorities authorities = users.loadAuthorities(user.id());
        List<GrantedAuthority> granted = new ArrayList<>();
        authorities.roles().forEach(role -> granted.add(new SimpleGrantedAuthority(Jacky917AuthorityPrefix.ROLE + role)));
        authorities.permissions().forEach(permission ->
                granted.add(new SimpleGrantedAuthority(Jacky917AuthorityPrefix.PERMISSION + permission)));
        return User.withUsername(user.id())
                .password(passwordHash)
                .authorities(granted)
                .disabled(user.status() == UserStatus.DISABLED)
                .accountLocked(user.status() == UserStatus.LOCKED || user.isTemporarilyLocked(now))
                .build();
    }
}
