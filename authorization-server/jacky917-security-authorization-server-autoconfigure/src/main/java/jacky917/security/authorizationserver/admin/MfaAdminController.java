package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.mfa.MfaService;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * A user's two-step verification in the administration API (phase 3 and 4
 * design §7): reading its state, and turning it off for a user who lost
 * both the authenticator app and the recovery codes.
 * <p>
 * 管理 API 中使用者的兩步驟驗證（第 3、4 階段設計 §7）：查詢狀態，以及為同時
 * 遺失驗證器 App 與復原碼的使用者停用。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api/users/{userId}/mfa")
public class MfaAdminController {

    private final MfaService mfa;
    private final UserAccountService users;
    private final AdminAuditService audit;
    private final ApplicationEventPublisher events;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param mfa           reads and turns off two-step verification
     *                      <br>查詢與停用兩步驟驗證
     * @param users         checks that the user exists
     *                      <br>確認使用者存在
     * @param audit         records the reset in {@code admin_audit_log}
     *                      <br>在 {@code admin_audit_log} 記錄重設
     * @param events        records it in the user's {@code login_audit} as
     *                      {@code MFA_DISABLED}
     *                      <br>在使用者的 {@code login_audit} 記錄
     *                      {@code MFA_DISABLED}
     * @param transactions  turns it off and records it together
     *                      <br>在同一個交易中停用並記錄
     * @param clock         the clock
     *                      <br>時鐘
     */
    public MfaAdminController(MfaService mfa, UserAccountService users, AdminAuditService audit,
                              ApplicationEventPublisher events, TransactionOperations transactions, Clock clock) {
        this.mfa = mfa;
        this.users = users;
        this.audit = audit;
        this.events = events;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Returns the state of a user's two-step verification.
     * <p>
     * 回傳使用者的兩步驟驗證狀態。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the state
     *         <br>狀態
     * @throws AdminApiException {@code 404} if there is no such user
     *         <br>使用者不存在時為 {@code 404}
     */
    @GetMapping
    public MfaView status(@PathVariable String userId) {
        requireUser(userId);
        Optional<MfaService.Status> status = mfa.status(userId);
        return new MfaView(status.isPresent(), status.map(MfaService.Status::enabledAt).orElse(null),
                status.map(MfaService.Status::remainingRecoveryCodes).orElse(0), mfa.isRequired(userId));
    }

    /**
     * Turns a user's two-step verification off and deletes the recovery
     * codes; the user can turn it on again, and must at the next login if
     * a role requires it.
     * <p>
     * 停用使用者的兩步驟驗證並刪除復原碼；使用者可以再次啟用，若角色要求則下次
     * 登入時必須啟用。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @throws AdminApiException {@code 404} if there is no such user or it
     *         was not on
     *         <br>使用者不存在或未啟用時為 {@code 404}
     */
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void reset(@PathVariable String userId) {
        requireUser(userId);
        transactions.executeWithoutResult(tx -> {
            if (!mfa.disable(userId)) {
                throw AdminApiException.notFound("Two-step verification of user " + userId);
            }
            audit.record("USER_MFA_RESET", AdminAuditTarget.USER, userId, Map.of("mfaEnabled", true),
                    Map.of("mfaEnabled", false));
        });
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.MFA_DISABLED, clock.instant(), true)
                .userId(userId).currentRequest().build());
    }

    private void requireUser(String userId) {
        if (users.findById(userId).isEmpty()) {
            throw AdminApiException.notFound("User " + userId);
        }
    }

    /**
     * The state of a user's two-step verification.
     * <p>
     * 使用者的兩步驟驗證狀態。
     *
     * @param enabled                 whether it is on
     *                                <br>是否已啟用
     * @param enabledAt               when it was turned on, or {@code null}
     *                                <br>啟用時間，或 {@code null}
     * @param remainingRecoveryCodes  how many recovery codes are left
     *                                <br>剩餘的復原碼數量
     * @param required                whether a role of the user requires it
     *                                <br>使用者的角色是否要求
     */
    public record MfaView(boolean enabled, @Nullable Instant enabledAt, int remainingRecoveryCodes,
                          boolean required) {
    }
}
