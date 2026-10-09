package jacky917.security.authorizationserver.mfa;

import jacky917.security.authorizationserver.session.LoginMethod;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * A login that passed the first step and waits for two-step verification
 * (phase 3 and 4 design §7.2). It lives in the browser session; until it
 * is completed the browser is not logged in and no login session exists.
 * <p>
 * 已通過第一步、等待兩步驟驗證的登入（第 3、4 階段設計 §7.2）。存放在瀏覽器
 * Session 中；完成之前瀏覽器不是已登入狀態，也沒有登入 Session。
 *
 * @param userId          the user
 *                        <br>使用者
 * @param method          how the user logged in
 *                        <br>登入方式
 * @param idp             the identity provider
 *                        <br>身分提供者
 * @param amr             the authentication methods so far, comma-separated
 *                        <br>目前為止的驗證方式，以逗號分隔
 * @param authentication  the authentication of the first step
 *                        <br>第一步的驗證結果
 * @param continuation    what else the login does once completed
 *                        <br>完成後登入還要做的事
 * @param startedAt       when the first step passed
 *                        <br>第一步通過的時間
 * @param failures        wrong codes so far
 *                        <br>目前為止輸入錯誤的次數
 * @param setupSecret     the new secret to turn two-step verification on
 *                        with, when the user must do so first
 *                        ({@code mfa.required-roles}); {@code null}
 *                        otherwise. It ends with the pending login, so it
 *                        never reaches another user of the browser.
 *                        <br>使用者必須先啟用兩步驟驗證時
 *                        （{@code mfa.required-roles}）用來啟用的新密鑰，否則
 *                        為 {@code null}。它隨待驗證的登入一起結束，因此不會
 *                        留給同一個瀏覽器的下一位使用者。
 * @author Jacky
 * @since 2.1.0
 */
public record PendingLogin(String userId, LoginMethod method, String idp, String amr, Authentication authentication,
                           Continuation continuation, Instant startedAt, int failures, @Nullable String setupSecret)
        implements Serializable {

    /**
     * The browser session attribute that holds the pending login.
     * <p>
     * 存放待驗證登入的瀏覽器 Session 屬性。
     */
    public static final String SESSION_ATTRIBUTE = PendingLogin.class.getName();

    /**
     * How long a pending login can wait.
     * <p>
     * 待驗證的登入可以等待多久。
     */
    public static final Duration TIMEOUT = Duration.ofMinutes(5);

    /**
     * How many wrong codes end a pending login.
     * <p>
     * 輸入錯誤幾次後結束待驗證的登入。
     */
    public static final int MAX_FAILURES = 5;

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Returns whether the user must turn two-step verification on before
     * the login completes.
     * <p>
     * 回傳使用者是否必須在登入完成前啟用兩步驟驗證。
     *
     * @return {@code true} if {@link #setupSecret()} is set
     *         <br>{@code setupSecret} 有值時為 {@code true}
     */
    public boolean enrollment() {
        return setupSecret != null;
    }

    /**
     * Returns whether the pending login can still be completed.
     * <p>
     * 回傳待驗證的登入是否仍可完成。
     *
     * @param now  the current time
     *             <br>目前時間
     * @return {@code true} before {@link #TIMEOUT} passed
     *         <br>未超過 {@code TIMEOUT} 時為 {@code true}
     */
    public boolean isFresh(Instant now) {
        return now.isBefore(startedAt.plus(TIMEOUT));
    }

    /**
     * Returns this pending login with one more wrong code.
     * <p>
     * 回傳多一次輸入錯誤的待驗證登入。
     *
     * @return the pending login
     *         <br>待驗證的登入
     */
    public PendingLogin withFailure() {
        return new PendingLogin(userId, method, idp, amr, authentication, continuation, startedAt, failures + 1,
                setupSecret);
    }

    /**
     * What a login does after it is completed, besides creating the login
     * session.
     * <p>
     * 登入完成後，除了建立登入 Session 之外還要做的事。
     */
    public enum Continuation {

        /**
         * A password login: a forced password change may come next.
         * <p>
         * 密碼登入：接著可能必須變更密碼。
         */
        PASSWORD,

        /**
         * A login through an identity provider: a link waiting for this
         * login is completed.
         * <p>
         * 第三方登入：完成等待此登入的帳號連結。
         */
        FEDERATED,

        /**
         * A link confirmed with the password: the link is created only once
         * the second step passes.
         * <p>
         * 以密碼確認的帳號連結：第二步通過後才建立連結。
         */
        LINK
    }
}
