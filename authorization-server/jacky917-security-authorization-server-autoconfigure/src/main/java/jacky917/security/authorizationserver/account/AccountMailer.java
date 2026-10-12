package jacky917.security.authorizationserver.account;

/**
 * Sends the emails about users' accounts: email verification, password
 * reset and notices (phase 3 and 4 design D26).
 * <p>
 * 寄出關於使用者帳號的信件：Email 驗證、重設密碼與通知（第 3、4 階段設計
 * D26）。
 * <p>
 * The starter uses Spring's {@code JavaMailSender} when the application has
 * one, and otherwise writes the links to the log only when
 * {@code account.mail.log-links=true}. An application can provide its own
 * bean instead, for example to send through an email service API.
 * <p>
 * 應用程式有 Spring 的 {@code JavaMailSender} 時，starter 以它寄信；否則只有在
 * {@code account.mail.log-links=true} 時把連結寫入日誌。應用程式也可以自行
 * 提供 Bean 取代，例如透過寄信服務的 API 寄送。
 *
 * @author Jacky
 * @since 2.1.0
 */
public interface AccountMailer {

    /**
     * Returns whether mails can be sent; features that need them are
     * offered only when they can.
     * <p>
     * 回傳是否可以寄信；需要寄信的功能只在可以寄信時提供。
     *
     * @return {@code true} if {@link #send} delivers mails
     *         <br>{@code send} 會寄出信件時為 {@code true}
     */
    boolean isAvailable();

    /**
     * Sends a mail.
     * <p>
     * 寄出一封信。
     *
     * @param mail  the mail
     *              <br>信件
     * @throws IllegalStateException if mails cannot be sent
     *         <br>若無法寄信
     * @throws RuntimeException if delivery fails; callers log it and answer
     *         the user as if it had been sent, so the page reveals nothing
     *         <br>若寄送失敗；呼叫端會記錄日誌，並以已寄出的方式回應使用者，
     *         頁面因此不會透露任何資訊
     */
    void send(AccountMail mail);
}
