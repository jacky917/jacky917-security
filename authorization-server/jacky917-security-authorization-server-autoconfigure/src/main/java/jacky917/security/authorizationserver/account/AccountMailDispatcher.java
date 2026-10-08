package jacky917.security.authorizationserver.account;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

/**
 * Sends account mails in the background, so the pages answer at once in
 * every case: whether a mail was sent cannot be told from the response
 * time, and a slow mail server cannot hold a request thread.
 * <p>
 * 在背景寄出帳號信件，讓頁面在任何情況下都立即回應：無法從回應時間判斷是否
 * 寄了信，緩慢的郵件伺服器也不會卡住請求執行緒。
 * <p>
 * A failure is logged at {@code ERROR} with its cause and published as an
 * {@link AccountMailFailedEvent}; it never reaches the page.
 * <p>
 * 寄送失敗時以 {@code ERROR} 記錄原因，並發布 {@code AccountMailFailedEvent}；
 * 頁面不會受影響。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class AccountMailDispatcher implements AutoCloseable {

    private final AccountMailer mailer;
    private final Executor executor;
    private final ApplicationEventPublisher events;

    /**
     * Creates the dispatcher.
     * <p>
     * 建立 dispatcher。
     *
     * @param mailer    sends the mails
     *                  <br>寄出信件
     * @param executor  runs the sending; tests may run it at once
     *                  <br>執行寄送；測試可以立即執行
     * @param events    publishes the failures
     *                  <br>發布失敗事件
     */
    public AccountMailDispatcher(AccountMailer mailer, Executor executor, ApplicationEventPublisher events) {
        this.mailer = mailer;
        this.executor = executor;
        this.events = events;
    }

    /**
     * Returns whether mails can be sent.
     * <p>
     * 回傳是否可以寄信。
     *
     * @return {@link AccountMailer#isAvailable()}
     *         <br>{@code AccountMailer#isAvailable()}
     */
    public boolean isAvailable() {
        return mailer.isAvailable();
    }

    /**
     * Sends a mail in the background.
     * <p>
     * 在背景寄出一封信。
     *
     * @param mail    the mail
     *                <br>信件
     * @param userId  the user it is for, for the log
     *                <br>收件的使用者，用於日誌
     */
    public void send(AccountMail mail, String userId) {
        executor.execute(() -> deliver(mail, userId));
    }

    /**
     * Waits for the mails being sent and stops the executor, if it can be
     * stopped; called when the application context closes.
     * <p>
     * 等待正在寄出的信件並停止 executor（若可停止）；應用程式 context 關閉時
     * 呼叫。
     */
    @Override
    public void close() {
        if (executor instanceof ExecutorService service) {
            service.close();
        }
    }

    private void deliver(AccountMail mail, String userId) {
        try {
            mailer.send(mail);
            log.info("Sent the {} mail to user {}", mail.type(), userId);
        } catch (RuntimeException ex) {
            String reason = reason(ex);
            switch (reason) {
                case "authentication" -> log.error("Cannot send the {} mail to user {}: the mail server refused "
                        + "the login; check spring.mail.username and spring.mail.password", mail.type(), userId, ex);
                case "delivery" -> log.error("Cannot send the {} mail to user {}: the mail server failed",
                        mail.type(), userId, ex);
                default -> log.error("Cannot build the {} mail to user {}: this is a bug or a configuration error",
                        mail.type(), userId, ex);
            }
            events.publishEvent(new AccountMailFailedEvent(mail.type(), reason));
        }
    }

    private static String reason(RuntimeException ex) {
        // spring-context-support（org.springframework.mail）是選用依賴：以類別名稱判斷，不直接引用
        for (Class<?> type = ex.getClass(); type != null; type = type.getSuperclass()) {
            if ("org.springframework.mail.MailAuthenticationException".equals(type.getName())) {
                return "authentication";
            }
            if ("org.springframework.mail.MailException".equals(type.getName())) {
                return "delivery";
            }
        }
        return "internal";
    }
}
