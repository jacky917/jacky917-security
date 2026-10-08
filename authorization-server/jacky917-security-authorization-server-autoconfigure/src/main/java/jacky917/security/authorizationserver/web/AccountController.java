package jacky917.security.authorizationserver.web;

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
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The account page: the devices where the user is logged in, and logging
 * out of one or all of them (detailed design §5.6).
 * <p>
 * 帳號頁：使用者登入中的裝置，以及登出其中一個或全部裝置（詳細設計 §5.6）。
 * <p>
 * Logging out of a device revokes its login session, so its refresh token
 * stops working at once; the access tokens already issued stay valid until
 * they expire (at most the access token lifetime). Logging out of the
 * current device, or of all devices, also ends this browser login.
 * <p>
 * 登出某個裝置會撤銷其登入 Session，Refresh Token 立即失效；已簽發的 Access
 * Token 仍有效至到期（最長為 Access Token 有效期）。登出目前的裝置或所有裝置
 * 時，也會結束此瀏覽器的登入。
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

    private static final String[] PAGE_KEYS = {"account.title", "account.devices", "account.current",
            "account.signed-in-at", "account.last-active", "account.logout", "account.logout-all",
            "account.logout-all.hint", "account.ip"};

    private final AuthSessionService sessions;
    private final UserAccountService users;
    private final Jacky917LogoutHandler logoutHandler;
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
     * @param zone           the time zone in which times are shown
     *                       <br>顯示時間所用的時區
     */
    public AccountController(AuthorizationServerProperties properties, AuthSessionService sessions,
                             UserAccountService users, Jacky917LogoutHandler logoutHandler, ZoneId zone) {
        this.sessions = sessions;
        this.users = users;
        this.logoutHandler = logoutHandler;
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
        return "jacky917/account";
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
     * Logs out of every device, including this one.
     * <p>
     * 登出所有裝置，包含目前這一個。
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
        for (AuthSession session : sessions.findActive(authentication.getName())) {
            logoutHandler.end(session.sessionId(), RevokeReason.LOGOUT_ALL, null, request);
        }
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
