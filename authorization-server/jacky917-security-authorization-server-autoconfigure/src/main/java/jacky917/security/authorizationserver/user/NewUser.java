package jacky917.security.authorizationserver.user;

import org.jspecify.annotations.Nullable;

import java.util.Set;

/**
 * Data for creating a user account.
 * <p>
 * 建立使用者帳號所需的資料。
 *
 * @param username       the login name (3-64 characters, no {@code @}),
 *                       or {@code null}
 *                       <br>登入帳號（3～64 字元，不可含 {@code @}），或
 *                       {@code null}
 * @param email          the email, or {@code null}
 *                       <br>Email，或 {@code null}
 * @param emailVerified  whether the email is verified; only verified
 *                       emails can be used to log in
 *                       <br>Email 是否已驗證；只有已驗證的 Email 可以用來登入
 * @param rawPassword    the password, checked against the password policy,
 *                       or {@code null} for no password
 *                       <br>密碼，會依密碼政策檢查；{@code null} 表示沒有密碼
 * @param displayName    the display name, or {@code null}
 *                       <br>顯示名稱，或 {@code null}
 * @param roles          role codes to grant; {@code USER} is always added
 *                       <br>要指派的角色代碼；一律加上 {@code USER}
 * @author Jacky
 * @since 2.1.0
 */
public record NewUser(
        @Nullable String username,
        @Nullable String email,
        boolean emailVerified,
        @Nullable String rawPassword,
        @Nullable String displayName,
        Set<String> roles) {
}
