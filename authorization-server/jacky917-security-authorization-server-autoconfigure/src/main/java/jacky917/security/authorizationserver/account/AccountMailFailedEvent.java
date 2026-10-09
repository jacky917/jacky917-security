package jacky917.security.authorizationserver.account;

import java.util.Objects;

/**
 * Published when an account mail could not be sent. The page the user saw
 * did not change, so this event and the {@code ERROR} log are the only
 * signs; the metric {@code jacky917.as.mail.failures} counts it.
 * <p>
 * 帳號信件無法寄出時發布。使用者看到的頁面不會改變，因此這個事件與
 * {@code ERROR} 日誌是唯一的線索；metric {@code jacky917.as.mail.failures}
 * 會計入。
 *
 * @param type    the kind of mail
 *                <br>信件種類
 * @param reason  {@code authentication} (the mail server refused the
 *                login), {@code delivery} (any other error of the mail
 *                server) or {@code internal} (building the mail failed: a
 *                bug or a configuration error)
 *                <br>{@code authentication}（郵件伺服器拒絕登入）、
 *                {@code delivery}（郵件伺服器的其他錯誤）或 {@code internal}
 *                （產生信件失敗：程式或設定錯誤）
 * @author Jacky
 * @since 2.1.0
 */
public record AccountMailFailedEvent(AccountMail.Type type, String reason) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     *
     * @param type    the kind of mail
     *                <br>信件種類
     * @param reason  why it failed
     *                <br>失敗原因
     */
    public AccountMailFailedEvent {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(reason, "reason");
    }
}
