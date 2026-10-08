package jacky917.security.authorizationserver.audit;

import jacky917.security.authorizationserver.session.LoginMethod;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Objects;

/**
 * A security event for {@code login_audit} (detailed design §8.1).
 * <p>
 * 寫入 {@code login_audit} 的安全事件（詳細設計 §8.1）。
 * <p>
 * Components publish it with Spring's {@code ApplicationEventPublisher}
 * after their transaction has committed, so an event never describes a
 * change that was rolled back. Listeners run synchronously in the
 * publishing thread; {@link JdbcLoginAuditListener} writes to the same
 * database, which on SQLite would wait for the publisher's own write lock if
 * the event were published inside the transaction. Applications can listen
 * to the same event, for example to forward it to a SIEM.
 * <p>
 * 元件在交易提交之後以 Spring 的 {@code ApplicationEventPublisher} 發布此事件，
 * 因此事件不會描述已回滾的變更。Listener 在發布的執行緒中同步執行；
 * {@code JdbcLoginAuditListener} 寫入同一個資料庫，若在交易內發布，SQLite 上
 * 會等待發布者自己持有的寫入鎖。應用程式也可以監聽同一個事件，例如轉送到
 * SIEM。
 * <p>
 * A successful event never has a failure reason. Failed {@code LOGIN}
 * events always have one; other failed events may not.
 * <p>
 * 成功的事件一定沒有失敗原因。失敗的 {@code LOGIN} 事件一定有失敗原因；其他
 * 失敗事件則不一定有。
 *
 * @param type                the event type
 *                            <br>事件種類
 * @param occurredAt          when it happened
 *                            <br>發生時間
 * @param success             whether the action succeeded
 *                            <br>動作是否成功
 * @param userId              the user, or {@code null} if unknown
 *                            <br>使用者；不明時為 {@code null}
 * @param usernameAttempted   the login name typed on a failed login, or
 *                            {@code null}
 *                            <br>登入失敗時輸入的帳號，或 {@code null}
 * @param loginMethod         how the user logged in, or {@code null}
 *                            <br>登入方式，或 {@code null}
 * @param idp                 the identity provider, or {@code null}
 *                            <br>身分提供者，或 {@code null}
 * @param registeredClientId  the client, or {@code null}
 *                            <br>client，或 {@code null}
 * @param sessionId           the login session ({@code asid}), or
 *                            {@code null}
 *                            <br>登入 Session（{@code asid}），或 {@code null}
 * @param failureReason       why it failed, or {@code null}
 *                            <br>失敗原因，或 {@code null}
 * @param ipAddress           the client IP address, or {@code null}
 *                            <br>用戶端 IP，或 {@code null}
 * @param userAgent           the user agent, or {@code null}
 *                            <br>User-Agent，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record LoginAuditEvent(
        LoginAuditEventType type,
        Instant occurredAt,
        boolean success,
        @Nullable String userId,
        @Nullable String usernameAttempted,
        @Nullable LoginMethod loginMethod,
        @Nullable String idp,
        @Nullable String registeredClientId,
        @Nullable String sessionId,
        @Nullable LoginFailureReason failureReason,
        @Nullable String ipAddress,
        @Nullable String userAgent) {

    /**
     * Creates an event, checking that its values fit together.
     * <p>
     * 建立事件，並檢查各值是否一致。
     *
     * @throws IllegalArgumentException if a successful event has a failure
     *         reason
     *         <br>若成功的事件帶有失敗原因
     */
    public LoginAuditEvent {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(occurredAt, "occurredAt");
        if (success && failureReason != null) {
            throw new IllegalArgumentException("A successful " + type + " event has the failure reason "
                    + failureReason);
        }
    }

    /**
     * Starts building an event.
     * <p>
     * 開始建立事件。
     *
     * @param type        the event type
     *                    <br>事件種類
     * @param occurredAt  when it happened
     *                    <br>發生時間
     * @param success     whether the action succeeded
     *                    <br>動作是否成功
     * @return the builder
     *         <br>builder
     */
    public static Builder builder(LoginAuditEventType type, Instant occurredAt, boolean success) {
        return new Builder(type, occurredAt, success);
    }

    /**
     * Builder of {@link LoginAuditEvent}; every optional value starts as
     * {@code null}.
     * <p>
     * {@code LoginAuditEvent} 的 builder；所有選填值的初始值為 {@code null}。
     */
    public static final class Builder {

        private final LoginAuditEventType type;
        private final Instant occurredAt;
        private final boolean success;
        private @Nullable String userId;
        private @Nullable String usernameAttempted;
        private @Nullable LoginMethod loginMethod;
        private @Nullable String idp;
        private @Nullable String registeredClientId;
        private @Nullable String sessionId;
        private @Nullable LoginFailureReason failureReason;
        private @Nullable String ipAddress;
        private @Nullable String userAgent;

        private Builder(LoginAuditEventType type, Instant occurredAt, boolean success) {
            this.type = type;
            this.occurredAt = occurredAt;
            this.success = success;
        }

        /**
         * Sets the user.
         * <p>
         * 設定使用者。
         *
         * @param userId  the user id, or {@code null}
         *                <br>使用者 ID，或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder userId(@Nullable String userId) {
            this.userId = userId;
            return this;
        }

        /**
         * Sets the login name typed on a failed login.
         * <p>
         * 設定登入失敗時輸入的帳號。
         *
         * @param usernameAttempted  the typed login name, or {@code null}
         *                           <br>輸入的帳號，或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder usernameAttempted(@Nullable String usernameAttempted) {
            this.usernameAttempted = usernameAttempted;
            return this;
        }

        /**
         * Sets how the user logged in and through which provider.
         * <p>
         * 設定登入方式與身分提供者。
         *
         * @param loginMethod  how the user logged in, or {@code null}
         *                     <br>登入方式，或 {@code null}
         * @param idp          the identity provider, or {@code null}
         *                     <br>身分提供者，或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder login(@Nullable LoginMethod loginMethod, @Nullable String idp) {
            this.loginMethod = loginMethod;
            this.idp = idp;
            return this;
        }

        /**
         * Sets the client.
         * <p>
         * 設定 client。
         *
         * @param registeredClientId  the {@code oauth2_registered_client.id},
         *                            or {@code null}
         *                            <br>{@code oauth2_registered_client.id}，
         *                            或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder registeredClientId(@Nullable String registeredClientId) {
            this.registeredClientId = registeredClientId;
            return this;
        }

        /**
         * Sets the login session.
         * <p>
         * 設定登入 Session。
         *
         * @param sessionId  the session id ({@code asid}), or {@code null}
         *                   <br>Session ID（{@code asid}），或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder sessionId(@Nullable String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * Sets why the action failed.
         * <p>
         * 設定失敗原因。
         *
         * @param failureReason  why it failed, or {@code null}
         *                       <br>失敗原因，或 {@code null}
         * @return this builder
         *         <br>此 builder
         */
        public Builder failureReason(@Nullable LoginFailureReason failureReason) {
            this.failureReason = failureReason;
            return this;
        }

        /**
         * Sets the IP address and user agent from the given request.
         * <p>
         * 從指定的請求設定 IP 與 User-Agent。
         *
         * @param request  the request, or {@code null} to leave them unset
         *                 <br>請求；{@code null} 時不設定
         * @return this builder
         *         <br>此 builder
         */
        public Builder request(@Nullable HttpServletRequest request) {
            if (request != null) {
                this.ipAddress = request.getRemoteAddr();
                this.userAgent = request.getHeader(HttpHeaders.USER_AGENT);
            }
            return this;
        }

        /**
         * Sets the IP address and user agent from the request bound to the
         * current thread, if any.
         * <p>
         * 若目前執行緒綁定了請求，從該請求設定 IP 與 User-Agent。
         *
         * @return this builder
         *         <br>此 builder
         */
        public Builder currentRequest() {
            return request(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet
                    ? servlet.getRequest() : null);
        }

        /**
         * Creates the event.
         * <p>
         * 建立事件。
         *
         * @return the event
         *         <br>事件
         * @throws IllegalArgumentException if a successful event has a
         *         failure reason
         *         <br>若成功的事件帶有失敗原因
         */
        public LoginAuditEvent build() {
            return new LoginAuditEvent(type, occurredAt, success, userId, usernameAttempted, loginMethod, idp,
                    registeredClientId, sessionId, failureReason, ipAddress, userAgent);
        }
    }
}
