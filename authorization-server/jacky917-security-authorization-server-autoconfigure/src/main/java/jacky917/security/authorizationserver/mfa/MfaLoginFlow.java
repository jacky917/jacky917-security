package jacky917.security.authorizationserver.mfa;

import jacky917.security.authorizationserver.account.AccountPaths;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.time.Clock;

/**
 * Puts two-step verification between the first step of a login and the
 * login session (phase 3 and 4 design §7.2). Password logins, logins
 * through an identity provider and links confirmed with a password all
 * pass through it.
 * <p>
 * 在登入的第一步與登入 Session 之間加入兩步驟驗證（第 3、4 階段設計 §7.2）。
 * 密碼登入、第三方登入與以密碼確認的帳號連結都會經過這裡。
 * <ul>
 *   <li>A user who turned two-step verification on is sent to
 *       {@code /jacky917/mfa}; a user with a role in
 *       {@code mfa.required-roles} who has not is sent to
 *       {@code /jacky917/mfa/setup}. In both cases the browser is logged
 *       out until the second step passes.
 *       <br>已啟用兩步驟驗證的使用者被導向 {@code /jacky917/mfa}；擁有
 *       {@code mfa.required-roles} 中的角色卻尚未啟用的使用者被導向
 *       {@code /jacky917/mfa/setup}。兩種情況在第二步通過之前，瀏覽器都不是
 *       已登入狀態。</li>
 *   <li>Completing the login creates the login session with {@code otp}
 *       added to {@code amr}.
 *       <br>完成登入時建立登入 Session，{@code amr} 加上 {@code otp}。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class MfaLoginFlow {

    private final MfaService mfa;
    private final LoginCompletion completion;
    private final UserAccountService users;
    private final Clock clock;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    /**
     * Creates the flow.
     * <p>
     * 建立流程。
     *
     * @param mfa         tells whether a user needs the second step
     *                    <br>判斷使用者是否需要第二步
     * @param completion  logs the user in once the second step passes
     *                    <br>第二步通過後讓使用者登入
     * @param users       tells whether the password must be changed
     *                    <br>判斷是否必須變更密碼
     * @param clock       the clock
     *                    <br>時鐘
     */
    public MfaLoginFlow(MfaService mfa, LoginCompletion completion, UserAccountService users, Clock clock) {
        this.mfa = mfa;
        this.completion = completion;
        this.users = users;
        this.clock = clock;
    }

    /**
     * Starts the second step if the user needs it.
     * <p>
     * 若使用者需要第二步，開始第二步。
     *
     * @param userId          the user who passed the first step
     *                        <br>通過第一步的使用者
     * @param method          how the user logged in
     *                        <br>登入方式
     * @param idp             the identity provider
     *                        <br>身分提供者
     * @param amr             the authentication methods so far
     *                        <br>目前為止的驗證方式
     * @param authentication  the authentication of the first step
     *                        <br>第一步的驗證結果
     * @param continuation    what else the login does once completed
     *                        <br>完成後登入還要做的事
     * @param request         the current request
     *                        <br>目前的請求
     * @param response        the current response
     *                        <br>目前的回應
     * @return {@code true} if the browser was sent to the second step, in
     *         which case the caller stops; {@code false} if the login can be
     *         completed now
     *         <br>瀏覽器已被導向第二步時為 {@code true}，呼叫端應停止；可立即
     *         完成登入時為 {@code false}
     * @throws IOException if the redirect fails
     *         <br>若重導失敗
     */
    public boolean challenge(String userId, LoginMethod method, String idp, String amr, Authentication authentication,
                             PendingLogin.Continuation continuation, HttpServletRequest request,
                             HttpServletResponse response) throws IOException {
        boolean enabled = mfa.isEnabled(userId);
        boolean enrollment = !enabled && mfa.isRequired(userId);
        if (!enabled && !enrollment) {
            return false;
        }
        // 第二步通過之前不是已登入狀態：授權端點因此會導向登入頁
        completion.restore(null, request, response);
        request.getSession().setAttribute(PendingLogin.SESSION_ATTRIBUTE, new PendingLogin(userId, method, idp, amr,
                authentication, continuation, clock.instant(), 0, enrollment));
        log.info("User {} passed the first step of a {} login; two-step verification {}", userId, method,
                enrollment ? "must be turned on" : "is next");
        response.sendRedirect(request.getContextPath() + (enrollment ? MfaPaths.SETUP : MfaPaths.VERIFY));
        return true;
    }

    /**
     * Returns the pending login of the browser, if it can still be
     * completed; an expired one is removed.
     * <p>
     * 回傳瀏覽器的待驗證登入（若仍可完成）；已逾時的會被移除。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return the pending login, or {@code null}
     *         <br>待驗證的登入，或 {@code null}
     */
    public @Nullable PendingLogin pending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(PendingLogin.SESSION_ATTRIBUTE) instanceof PendingLogin pending)) {
            return null;
        }
        if (!pending.isFresh(clock.instant())) {
            session.removeAttribute(PendingLogin.SESSION_ATTRIBUTE);
            return null;
        }
        return pending;
    }

    /**
     * Records a wrong code; the pending login ends after
     * {@link PendingLogin#MAX_FAILURES}.
     * <p>
     * 記錄一次錯誤的驗證碼；達到 {@code PendingLogin#MAX_FAILURES} 次後結束
     * 待驗證的登入。
     *
     * @param pending  the pending login
     *                 <br>待驗證的登入
     * @param request  the current request
     *                 <br>目前的請求
     * @return {@code true} if the pending login can still be completed
     *         <br>待驗證的登入仍可完成時為 {@code true}
     */
    public boolean recordFailure(PendingLogin pending, HttpServletRequest request) {
        PendingLogin next = pending.withFailure();
        if (next.failures() >= PendingLogin.MAX_FAILURES) {
            abandon(request);
            return false;
        }
        request.getSession().setAttribute(PendingLogin.SESSION_ATTRIBUTE, next);
        return true;
    }

    /**
     * Ends the pending login without logging in.
     * <p>
     * 結束待驗證的登入，不登入。
     *
     * @param request  the current request
     *                 <br>目前的請求
     */
    public void abandon(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(PendingLogin.SESSION_ATTRIBUTE);
        }
    }

    /**
     * Completes the pending login after the second step passed: a new
     * session id, the login session with {@code otp} in {@code amr}, and the
     * forced password change of a password login.
     * <p>
     * 第二步通過後完成待驗證的登入：更換 Session ID、建立 {@code amr} 含
     * {@code otp} 的登入 Session，以及密碼登入的強制變更密碼。
     *
     * @param pending   the pending login
     *                  <br>待驗證的登入
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     */
    public void complete(PendingLogin pending, HttpServletRequest request, HttpServletResponse response) {
        abandon(request);
        // 登入前更換 Session ID（session fixation）
        request.changeSessionId();
        completion.logIn(pending.userId(), pending.method(), pending.idp(), pending.amr() + ",otp",
                pending.authentication(), request, response);
        if (pending.continuation() == PendingLogin.Continuation.PASSWORD
                && users.findById(pending.userId()).map(UserAccount::passwordChangeRequired).orElse(false)) {
            request.getSession().setAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE, Boolean.TRUE);
        }
    }

    /**
     * Returns where the browser goes after the login is completed: the
     * password change page when it is required, otherwise the
     * authorization request that the login interrupted, or the signed-in
     * page.
     * <p>
     * 回傳登入完成後瀏覽器要前往的位置：必須變更密碼時為變更密碼頁，否則為被
     * 登入中斷的授權請求，或已登入頁。
     *
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     * @return the address
     *         <br>網址
     */
    public String target(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE) != null) {
            return request.getContextPath() + AccountPaths.CHANGE_PASSWORD;
        }
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved != null) {
            requestCache.removeRequest(request, response);
            return saved.getRedirectUrl();
        }
        return request.getContextPath() + LoginController.SIGNED_IN_PATH;
    }
}
