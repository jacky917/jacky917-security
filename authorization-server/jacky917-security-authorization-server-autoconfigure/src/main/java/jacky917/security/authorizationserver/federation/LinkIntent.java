package jacky917.security.authorizationserver.federation;

import org.springframework.security.core.Authentication;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * A request from the account page to link a provider, kept in the browser
 * session while the user logs in to the provider.
 * <p>
 * 帳號頁發出的連結提供者請求，在使用者登入提供者期間保存在瀏覽器 Session 中。
 *
 * @param userId     the user who asked for the link
 *                   <br>提出連結請求的使用者
 * @param provider   the registration id of the provider to link
 *                   <br>要連結之提供者的 registration id
 * @param previous   the browser's login before going to the provider,
 *                   restored afterwards
 *                   <br>前往提供者之前瀏覽器的登入，完成後還原
 * @param createdAt  when the request was made
 *                   <br>提出請求的時間
 * @author Jacky
 * @since 2.1.0
 */
public record LinkIntent(String userId, String provider, Authentication previous, Instant createdAt)
        implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Name of the browser session attribute holding the request.
     * <p>
     * 存放此請求的瀏覽器 Session 屬性名稱。
     */
    public static final String SESSION_ATTRIBUTE = LinkIntent.class.getName();

    /**
     * Name of the browser session attribute holding the token of a pending
     * link from {@link PendingLinkService}.
     * <p>
     * 存放 {@code PendingLinkService} 待確認連結 token 的瀏覽器 Session 屬性名稱。
     */
    public static final String PENDING_LINK_ATTRIBUTE = LinkIntent.class.getName() + ".PENDING";

    /**
     * How long the user has to finish the provider login.
     * <p>
     * 使用者完成提供者登入的期限。
     */
    public static final Duration LIFETIME = Duration.ofMinutes(10);

    /**
     * Returns whether the request can still be used.
     * <p>
     * 回傳此請求是否仍可使用。
     *
     * @param now  the current time
     *             <br>目前時間
     * @return {@code true} within {@link #LIFETIME} of its creation
     *         <br>建立後 {@code LIFETIME} 之內為 {@code true}
     */
    public boolean isFresh(Instant now) {
        return now.isBefore(createdAt.plus(LIFETIME));
    }
}
