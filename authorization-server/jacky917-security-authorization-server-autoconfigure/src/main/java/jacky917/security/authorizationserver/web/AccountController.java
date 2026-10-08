package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.LinkIntent;
import jacky917.security.authorizationserver.federation.LinkedIdentity;
import jacky917.security.authorizationserver.federation.UnlinkResult;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.Jacky917LogoutHandler;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.Clock;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The account page: the devices where the user is logged in, logging out of
 * one or all of them (detailed design §5.6), and the linked external
 * accounts (§5.3).
 * <p>
 * 帳號頁：使用者登入中的裝置、登出其中一個或全部裝置（詳細設計 §5.6），以及
 * 已連結的外部帳號（§5.3）。
 * <p>
 * Logging out of a device revokes its login session, so its refresh token
 * stops working at once; the access tokens already issued stay valid until
 * they expire (at most the access token lifetime). Logging out of the
 * current device, or of all devices, also ends this browser login.
 * <p>
 * 登出某個裝置會撤銷其登入 Session，Refresh Token 立即失效；已簽發的 Access
 * Token 仍有效至到期（最長為 Access Token 有效期）。登出目前的裝置或所有裝置
 * 時，也會結束此瀏覽器的登入。
 * <p>
 * Linking an external account starts a login with that provider and links
 * the result to this user (D06-D). An external account can be unlinked
 * unless it is the user's only way to log in. A link that failed is
 * explained at the top of the page.
 * <p>
 * 連結外部帳號時，以該提供者登入，並把結果連結到此使用者（D06-D）。外部帳號
 * 可以解除連結，除非它是使用者唯一的登入方式。連結失敗時，頁面上方會說明
 * 原因。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class AccountController {

    /**
     * Path of the account page.
     * <p>
     * 帳號頁的路徑。
     */
    public static final String ACCOUNT_PATH = "/jacky917/account";

    private static final List<String> ERRORS = List.of("link_failed", "link_expired", "linked_elsewhere",
            "provider_already_linked", "last_method");
    private static final String[] PAGE_KEYS = {"account.title", "account.devices", "account.current",
            "account.signed-in-at", "account.last-active", "account.logout", "account.logout-all",
            "account.logout-all.hint", "account.ip", "account.identities", "account.link", "account.unlink",
            "account.linked-at"};

    private final AuthSessionService sessions;
    private final UserAccountService users;
    private final Jacky917LogoutHandler logoutHandler;
    private final FederatedIdentityService identities;
    private final IdentityProviders providers;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final PageSupport page;
    private final ZoneId zone;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties     the authorization server properties
     *                       <br>Authorization Server 設定屬性
     * @param sessions       the login sessions
     *                       <br>登入 Session
     * @param users          the user accounts
     *                       <br>使用者帳號
     * @param logoutHandler  ends login sessions
     *                       <br>結束登入 Session
     * @param identities     the linked external accounts
     *                       <br>已連結的外部帳號
     * @param providers      the identity providers that can be linked
     *                       <br>可以連結的身分提供者
     * @param events         publishes the audit events
     *                       <br>發布稽核事件
     * @param clock          the clock
     *                       <br>時鐘
     * @param zone           the time zone in which times are shown
     *                       <br>顯示時間所用的時區
     */
    public AccountController(AuthorizationServerProperties properties, AuthSessionService sessions,
                             UserAccountService users, Jacky917LogoutHandler logoutHandler,
                             FederatedIdentityService identities, IdentityProviders providers,
                             ApplicationEventPublisher events, Clock clock, ZoneId zone) {
        this.sessions = sessions;
        this.users = users;
        this.logoutHandler = logoutHandler;
        this.identities = identities;
        this.providers = providers;
        this.events = events;
        this.clock = clock;
        this.page = new PageSupport(properties.getBranding());
        this.zone = zone;
    }

    /**
     * Shows the account page.
     * <p>
     * 顯示帳號頁。
     *
     * @param authentication  the logged-in user; the name is the user id
     *                        <br>已登入的使用者，名稱即使用者 ID
     * @param request         the current request, for its language and
     *                        browser session
     *                        <br>目前的請求，用於判斷語言與瀏覽器 Session
     * @param model           the view model
     *                        <br>畫面資料
     * @return the account view
     *         <br>帳號頁面
     */
    @GetMapping(ACCOUNT_PATH)
    public String account(Authentication authentication, HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        String userId = authentication.getName();
        model.addAttribute("userName", users.findById(userId).map(AccountController::displayName).orElse(userId));
        DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z", locale).withZone(zone);
        String current = currentSessionId(request);
        List<Map<String, Object>> devices = new ArrayList<>();
        for (AuthSession session : sessions.findActive(userId)) {
            Map<String, Object> device = new LinkedHashMap<>();
            device.put("id", session.sessionId());
            device.put("method", session.loginMethod() == LoginMethod.PASSWORD
                    ? page.message("account.method.password", null, locale)
                    : page.message("account.method.federated", new Object[]{session.idp()}, locale));
            device.put("userAgent", session.userAgent());
            device.put("ip", session.ipAddress());
            device.put("signedInAt", format.format(session.createdAt()));
            device.put("lastActive", format.format(session.lastSeenAt()));
            device.put("current", session.sessionId().equals(current));
            devices.add(device);
        }
        model.addAttribute("devices", devices);
        model.addAttribute("identities", identities(userId, format));
        String error = request.getParameter("error");
        String pendingLinkError = takeLinkError(request);
        if (error == null) {
            error = pendingLinkError;
        }
        if (error != null && ERRORS.contains(error)) {
            model.addAttribute("error", page.message("account.error." + error, null, locale));
        }
        return "jacky917/account";
    }

    /**
     * Starts linking an external account: the browser logs in with the
     * provider and comes back to this page.
     * <p>
     * 開始連結外部帳號：瀏覽器以該提供者登入後回到此頁。
     *
     * @param registrationId  the provider to link
     *                        <br>要連結的提供者
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @return a redirect to the provider login
     *         <br>重導至提供者登入
     * @throws ResponseStatusException 404 if the provider is not offered
     *         <br>未提供此提供者時為 404
     */
    @PostMapping(ACCOUNT_PATH + "/link/{registrationId}")
    public String link(@PathVariable String registrationId, Authentication authentication,
                       HttpServletRequest request) {
        IdentityProviders.Provider provider = providers.find(registrationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        request.getSession().setAttribute(LinkIntent.SESSION_ATTRIBUTE,
                new LinkIntent(authentication.getName(), provider.registrationId(), authentication, clock.instant()));
        return "redirect:/oauth2/authorization/" + provider.registrationId();
    }

    /**
     * Unlinks an external account, unless it is the user's only way to log
     * in.
     * <p>
     * 解除外部帳號的連結，除非它是使用者唯一的登入方式。
     *
     * @param provider        the registration id of the provider
     *                        <br>提供者的 registration id
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @return a redirect to the account page
     *         <br>重導至帳號頁
     */
    @PostMapping(ACCOUNT_PATH + "/unlink/{provider}")
    public String unlink(@PathVariable String provider, Authentication authentication, HttpServletRequest request) {
        String userId = authentication.getName();
        UnlinkResult result = identities.unlink(userId, provider);
        switch (result) {
            case LAST_LOGIN_METHOD -> {
                return "redirect:" + ACCOUNT_PATH + "?error=last_method";
            }
            // 例如已在另一個分頁解除：已經是想要的狀態
            case NOT_LINKED -> {
                return "redirect:" + ACCOUNT_PATH;
            }
            case UNLINKED -> events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_UNLINKED,
                    clock.instant(), true).userId(userId).login(LoginMethod.FEDERATED, provider).request(request)
                    .build());
        }
        return "redirect:" + ACCOUNT_PATH;
    }

    /**
     * Returns and removes the error of a pending link that could not be
     * completed at login.
     * <p>
     * 回傳並移除登入時無法完成之待確認連結的錯誤。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return the error code, or {@code null} if there is none
     *         <br>錯誤代碼；沒有時為 {@code null}
     */
    static @Nullable String takeLinkError(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(FederatedLoginSuccessHandler.LINK_ERROR_ATTRIBUTE)
                instanceof String error)) {
            return null;
        }
        session.removeAttribute(FederatedLoginSuccessHandler.LINK_ERROR_ATTRIBUTE);
        return error;
    }

    private List<Map<String, Object>> identities(String userId, DateTimeFormatter format) {
        Map<String, LinkedIdentity> linked = new LinkedHashMap<>();
        identities.findLinked(userId).forEach(identity -> linked.put(identity.provider(), identity));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (IdentityProviders.Provider provider : providers.list()) {
            rows.add(identityRow(provider.registrationId(), provider.name(), linked.remove(provider.registrationId()),
                    format));
        }
        // 已連結、但已不在設定中的提供者仍列出，讓使用者可以解除連結
        linked.values().forEach(identity -> rows.add(identityRow(identity.provider(), identity.provider(), identity,
                format)));
        return rows;
    }

    private static Map<String, Object> identityRow(String registrationId, String name, @Nullable LinkedIdentity identity,
                                                   DateTimeFormatter format) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", registrationId);
        row.put("name", name);
        row.put("linked", identity != null);
        row.put("detail", identity == null ? null
                : identity.email() != null ? identity.email() : identity.displayName());
        row.put("linkedAt", identity == null ? null : format.format(identity.linkedAt()));
        return row;
    }

    /**
     * Logs out of one device. Logging out of the current device also ends
     * this browser login.
     * <p>
     * 登出一個裝置。登出目前的裝置時，也會結束此瀏覽器的登入。
     *
     * @param sessionId       the login session of the device
     *                        <br>該裝置的登入 Session
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param response        the current response
     *                        <br>目前的回應
     * @return a redirect to the account page, or to the login page after
     *         logging out of this device
     *         <br>重導至帳號頁；登出此裝置時重導至登入頁
     * @throws ResponseStatusException 404 if the session is not one of the
     *         user's
     *         <br>Session 不屬於該使用者時為 404
     */
    @PostMapping(ACCOUNT_PATH + "/sessions/{sessionId}/logout")
    public String logOutDevice(@PathVariable String sessionId, Authentication authentication,
                               HttpServletRequest request, HttpServletResponse response) {
        sessions.find(sessionId).filter(session -> session.userId().equals(authentication.getName()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (sessionId.equals(currentSessionId(request))) {
            logoutHandler.logout(request, response, authentication);
            return "redirect:/login?logout";
        }
        logoutHandler.end(sessionId, RevokeReason.LOGOUT, null, request);
        return "redirect:" + ACCOUNT_PATH;
    }

    /**
     * Logs out of every device, including this one. The sessions are revoked
     * in one transaction, so either all of them end or none does.
     * <p>
     * 登出所有裝置，包含目前這一個。所有 Session 在同一個交易中撤銷，因此要嘛全部
     * 結束，要嘛全部不變。
     *
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param response        the current response
     *                        <br>目前的回應
     * @return a redirect to the login page
     *         <br>重導至登入頁
     */
    @PostMapping(ACCOUNT_PATH + "/logout-all")
    public String logOutAllDevices(Authentication authentication, HttpServletRequest request,
                                   HttpServletResponse response) {
        logoutHandler.endAll(authentication.getName(), RevokeReason.LOGOUT_ALL, request);
        logoutHandler.logout(request, response, authentication);
        return "redirect:/login?logout";
    }

    private static @Nullable String currentSessionId(HttpServletRequest request) {
        HttpSession httpSession = request.getSession(false);
        return httpSession == null ? null : (String) httpSession.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
    }

    private static String displayName(UserAccount user) {
        for (String candidate : new String[]{user.displayName(), user.username(), user.email()}) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return user.id();
    }
}
