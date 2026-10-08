package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.web.AccountController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.time.Clock;

/**
 * Handles a login through an identity provider that failed before the
 * provider's user was known, for example an invalid ID token, a wrong client
 * secret, or the user cancelling at the provider (detailed design §5.3).
 * <p>
 * 處理在取得提供者使用者之前就失敗的第三方登入，例如 ID Token 無效、client
 * secret 錯誤，或使用者在提供者端取消（詳細設計 §5.3）。
 * <p>
 * The OAuth 2.0 error code is logged as a warning and a failed
 * {@code LOGIN} event with reason {@code FEDERATION} is audited, so a
 * misconfigured provider can be found without debug logging. When the user
 * started from the account page ({@link LinkIntent}), they are still logged
 * in and return to the account page; otherwise they return to the login
 * page.
 * <p>
 * OAuth 2.0 錯誤代碼記錄為警告，並稽核原因為 {@code FEDERATION} 的失敗
 * {@code LOGIN} 事件，因此不需要 debug 日誌也能找出設定錯誤的提供者。使用者
 * 從帳號頁發起時（{@code LinkIntent}）仍為登入狀態，回到帳號頁；其餘情況回到
 * 登入頁。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class FederatedLoginFailureHandler implements AuthenticationFailureHandler {

    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final RedirectStrategy redirects = new DefaultRedirectStrategy();

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param events  publishes the audit events
     *                <br>發布稽核事件
     * @param clock   the clock
     *                <br>時鐘
     */
    public FederatedLoginFailureHandler(ApplicationEventPublisher events, Clock clock) {
        this.events = events;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String code = exception instanceof OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode() : exception.getClass().getSimpleName();
        LinkIntent intent = takeLinkIntent(request);
        log.warn("A login through {} failed: {} ({})", intent == null ? "an identity provider" : intent.provider(),
                code, exception.getMessage());
        events.publishEvent(LoginAuditEvent.builder(intent == null ? LoginAuditEventType.LOGIN
                        : LoginAuditEventType.ACCOUNT_LINKED, clock.instant(), false)
                .userId(intent == null ? null : intent.userId())
                .login(LoginMethod.FEDERATED, intent == null ? null : intent.provider())
                .failureReason(LoginFailureReason.FEDERATION)
                .request(request)
                .build());
        redirects.sendRedirect(request, response, intent == null ? "/login?error=federation"
                : AccountController.ACCOUNT_PATH + "?error=link_failed");
    }

    private static @Nullable LinkIntent takeLinkIntent(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(LinkIntent.SESSION_ATTRIBUTE) instanceof LinkIntent intent)) {
            return null;
        }
        session.removeAttribute(LinkIntent.SESSION_ATTRIBUTE);
        return intent;
    }
}
