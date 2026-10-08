package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.admin.UserAdminService.CreateUserRequest;
import jacky917.security.authorizationserver.admin.UserAdminService.UserDetail;
import jacky917.security.authorizationserver.admin.UserAdminService.UserSummary;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.Jacky917LogoutHandler;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Users and their login sessions in the administration API (phase 3 and 4
 * design §4.2).
 * <p>
 * 管理 API 中的使用者與其登入 Session（第 3、4 階段設計 §4.2）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api")
public class UserAdminController {

    private final UserAdminService users;
    private final AuthSessionService sessions;
    private final Jacky917LogoutHandler logoutHandler;
    private final AdminAuditService audit;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param users          manages users
     *                       <br>管理使用者
     * @param sessions       the login sessions
     *                       <br>登入 Session
     * @param logoutHandler  ends login sessions and audits it
     *                       <br>結束登入 Session 並寫入稽核
     * @param audit          records the administration actions
     *                       <br>記錄管理操作
     */
    public UserAdminController(UserAdminService users, AuthSessionService sessions,
                               Jacky917LogoutHandler logoutHandler, AdminAuditService audit) {
        this.users = users;
        this.sessions = sessions;
        this.logoutHandler = logoutHandler;
        this.audit = audit;
    }

    /**
     * Searches users.
     * <p>
     * 搜尋使用者。
     *
     * @param query   part of the username, email or display name, or
     *                {@code null}
     *                <br>帳號、Email 或顯示名稱的一部分，或 {@code null}
     * @param status  only this status, or {@code null}
     *                <br>只列出此狀態，或 {@code null}
     * @param page    the zero-based page number
     *                <br>頁碼，從 0 開始
     * @param size    the page size, 1 to 200
     *                <br>每頁筆數，1～200
     * @return the users, newest first
     *         <br>使用者，新的在前
     */
    @GetMapping("/users")
    public PageResult<UserSummary> search(@RequestParam(required = false) @Nullable String query,
                                          @RequestParam(required = false) @Nullable UserStatus status,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "50") int size) {
        return users.search(query, status, page, size);
    }

    /**
     * Creates a user.
     * <p>
     * 建立使用者。
     *
     * @param request  the new user
     *                 <br>新的使用者
     * @return the created user
     *         <br>建立的使用者
     */
    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    public UserDetail create(@RequestBody CreateUserRequest request) {
        return users.create(request);
    }

    /**
     * Returns a user.
     * <p>
     * 回傳使用者。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the user with their roles and linked accounts
     *         <br>使用者及其角色與已連結的外部帳號
     */
    @GetMapping("/users/{userId}")
    public UserDetail find(@PathVariable String userId) {
        return users.find(userId);
    }

    /**
     * Changes some fields of a user.
     * <p>
     * 變更使用者的部分欄位。
     *
     * @param userId   the user id
     *                 <br>使用者 ID
     * @param changes  the fields to change
     *                 <br>要變更的欄位
     * @return the updated user
     *         <br>更新後的使用者
     */
    @PatchMapping("/users/{userId}")
    public UserDetail update(@PathVariable String userId, @RequestBody Map<String, Object> changes) {
        return users.update(userId, changes);
    }

    /**
     * Deletes a user.
     * <p>
     * 刪除使用者。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     */
    @DeleteMapping("/users/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String userId) {
        users.delete(userId);
    }

    /**
     * Ends a temporary lock.
     * <p>
     * 解除暫時鎖定。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the updated user
     *         <br>更新後的使用者
     */
    @PostMapping("/users/{userId}/unlock")
    public UserDetail unlock(@PathVariable String userId) {
        return users.unlock(userId);
    }

    /**
     * Sets a user's password.
     * <p>
     * 設定使用者的密碼。
     *
     * @param userId   the user id
     *                 <br>使用者 ID
     * @param request  the new password and whether it must be changed
     *                 <br>新密碼，以及是否必須變更
     */
    @PutMapping("/users/{userId}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void setPassword(@PathVariable String userId, @RequestBody SetPasswordRequest request) {
        users.setPassword(userId, request.password(), request.changeRequired());
    }

    /**
     * Gives a user a role.
     * <p>
     * 指派角色給使用者。
     *
     * @param userId   the user id
     *                 <br>使用者 ID
     * @param role     the role code
     *                 <br>角色代碼
     * @param request  when the role ends, or no body for never
     *                 <br>角色的到期時間；沒有本文表示不到期
     * @return the updated user
     *         <br>更新後的使用者
     */
    @PutMapping("/users/{userId}/roles/{role}")
    public UserDetail assignRole(@PathVariable String userId, @PathVariable String role,
                                 @RequestBody(required = false) @Nullable AssignRoleRequest request) {
        return users.assignRole(userId, role, request == null ? null : request.expiresAt());
    }

    /**
     * Removes a role from a user.
     * <p>
     * 移除使用者的角色。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @param role    the role code
     *                <br>角色代碼
     * @return the updated user
     *         <br>更新後的使用者
     */
    @DeleteMapping("/users/{userId}/roles/{role}")
    public UserDetail removeRole(@PathVariable String userId, @PathVariable String role) {
        return users.removeRole(userId, role);
    }

    /**
     * Lists the active login sessions of a user.
     * <p>
     * 列出使用者有效的登入 Session。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the sessions, most recently used first
     *         <br>登入 Session，最近使用的在前
     */
    @GetMapping("/users/{userId}/sessions")
    public List<SessionView> sessions(@PathVariable String userId) {
        users.summary(userId);
        return sessions.findActive(userId).stream().map(SessionView::of).toList();
    }

    /**
     * Revokes every login session of a user.
     * <p>
     * 撤銷使用者所有的登入 Session。
     *
     * @param userId   the user id
     *                 <br>使用者 ID
     * @param request  the current request, for the audit
     *                 <br>目前的請求，用於稽核
     * @return how many sessions were revoked
     *         <br>撤銷的 Session 數量
     */
    @DeleteMapping("/users/{userId}/sessions")
    public Map<String, Integer> revokeSessions(@PathVariable String userId, HttpServletRequest request) {
        users.summary(userId);
        int revoked = logoutHandler.endAll(userId, RevokeReason.ADMIN, request);
        audit.record("SESSIONS_REVOKED", AdminAuditTarget.USER, userId, null, Map.of("revoked", revoked));
        return Map.of("revoked", revoked);
    }

    /**
     * Revokes one login session.
     * <p>
     * 撤銷一個登入 Session。
     *
     * @param sessionId  the session id ({@code asid})
     *                   <br>Session ID（{@code asid}）
     * @param request    the current request, for the audit
     *                   <br>目前的請求，用於稽核
     * @throws AdminApiException {@code 404} if there is no such session
     *         <br>Session 不存在時為 {@code 404}
     */
    @DeleteMapping("/sessions/{sessionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revokeSession(@PathVariable String sessionId, HttpServletRequest request) {
        AuthSession session = sessions.find(sessionId)
                .orElseThrow(() -> AdminApiException.notFound("Session " + sessionId));
        if (logoutHandler.end(sessionId, RevokeReason.ADMIN, null, request)) {
            audit.record("SESSION_REVOKED", AdminAuditTarget.SESSION, sessionId, null,
                    Map.of("userId", session.userId()));
        }
    }

    /**
     * A new password.
     * <p>
     * 新密碼。
     *
     * @param password        the password
     *                        <br>密碼
     * @param changeRequired  whether it must be changed at the next login;
     *                        {@code null} means {@code true}
     *                        <br>下一次登入時是否必須變更；{@code null} 視為
     *                        {@code true}
     */
    public record SetPasswordRequest(@Nullable String password, @Nullable Boolean changeRequired) {
    }

    /**
     * How long a role is given.
     * <p>
     * 角色的期限。
     *
     * @param expiresAt  when the role ends, or {@code null} for never
     *                   <br>到期時間；{@code null} 表示不到期
     */
    public record AssignRoleRequest(@Nullable Instant expiresAt) {
    }

    /**
     * An active login session.
     * <p>
     * 有效的登入 Session。
     *
     * @param sessionId    the session id ({@code asid})
     *                     <br>Session ID（{@code asid}）
     * @param loginMethod  how the user logged in
     *                     <br>登入方式
     * @param idp          the identity provider
     *                     <br>身分提供者
     * @param createdAt    the login time
     *                     <br>登入時間
     * @param lastSeenAt   the last use
     *                     <br>最後使用時間
     * @param expiresAt    the absolute end
     *                     <br>絕對到期時間
     * @param ipAddress    the IP address at login, or {@code null}
     *                     <br>登入時的 IP，或 {@code null}
     * @param userAgent    the user agent at login, or {@code null}
     *                     <br>登入時的 User-Agent，或 {@code null}
     */
    public record SessionView(String sessionId, LoginMethod loginMethod, String idp, Instant createdAt,
                              Instant lastSeenAt, Instant expiresAt, @Nullable String ipAddress,
                              @Nullable String userAgent) {

        static SessionView of(AuthSession session) {
            return new SessionView(session.sessionId(), session.loginMethod(), session.idp(), session.createdAt(),
                    session.lastSeenAt(), session.expiresAt(), session.ipAddress(), session.userAgent());
        }
    }
}
