package jacky917.security.authorizationserver.federation;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * A provider account linked to a user, as shown on the account page.
 * <p>
 * 連結到使用者的提供者帳號，顯示於帳號頁。
 *
 * @param provider     the registration id of the provider
 *                     <br>提供者的 registration id
 * @param email        the email the provider reported, or {@code null}
 *                     <br>提供者回報的 Email，或 {@code null}
 * @param displayName  the name the provider reported, or {@code null}
 *                     <br>提供者回報的名稱，或 {@code null}
 * @param linkedAt     when it was linked
 *                     <br>連結時間
 * @param lastLoginAt  the last login through it, or {@code null}
 *                     <br>最後一次透過它登入的時間，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record LinkedIdentity(
        String provider,
        @Nullable String email,
        @Nullable String displayName,
        Instant linkedAt,
        @Nullable Instant lastLoginAt) {
}
