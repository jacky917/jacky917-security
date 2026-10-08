package jacky917.security.authorizationserver.federation;

import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * A user as reported by an external identity provider, in a common shape.
 * <p>
 * 外部身分提供者回報的使用者資料，轉換為統一的格式。
 *
 * @param provider       the registration id, for example {@code google}
 *                       <br>提供者的 registration id，例如 {@code google}
 * @param subject        the provider's stable user id
 *                       <br>提供者的穩定使用者 ID
 * @param email          the email, or {@code null}
 *                       <br>Email，或 {@code null}
 * @param emailVerified  whether the provider verified the email
 *                       <br>提供者是否已驗證此 Email
 * @param displayName    the display name, or {@code null}
 *                       <br>顯示名稱，或 {@code null}
 * @param avatarUrl      the picture URL, or {@code null}
 *                       <br>頭像網址，或 {@code null}
 * @param locale         the locale, or {@code null}
 *                       <br>語系，或 {@code null}
 * @param rawAttributes  the provider's attributes, kept for reference
 *                       <br>提供者的原始屬性，保留供查詢
 * @author Jacky
 * @since 2.1.0
 */
public record FederatedUserInfo(
        String provider,
        String subject,
        @Nullable String email,
        boolean emailVerified,
        @Nullable String displayName,
        @Nullable String avatarUrl,
        @Nullable String locale,
        Map<String, Object> rawAttributes) {
}
