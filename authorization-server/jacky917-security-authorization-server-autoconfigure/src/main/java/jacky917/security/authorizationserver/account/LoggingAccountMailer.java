package jacky917.security.authorizationserver.account;

import lombok.extern.slf4j.Slf4j;

/**
 * Writes account mails, including their links, to the log instead of
 * sending them ({@code account.mail.log-links=true}).
 * <p>
 * 不寄出帳號信件，而是把信件（包含連結）寫入日誌
 * （{@code account.mail.log-links=true}）。
 * <p>
 * <b>For development only</b>: anyone who can read the log can reset any
 * password. A warning is logged when it is created.
 * <p>
 * <b>僅限開發使用</b>：能讀取日誌的人就能重設任何人的密碼。建立時會記錄警告。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class LoggingAccountMailer implements AccountMailer {

    private final AccountMailContent content;

    /**
     * Creates the mailer and warns that it is for development only.
     * <p>
     * 建立 mailer，並警告僅限開發使用。
     *
     * @param content  writes the subject and text
     *                 <br>產生主旨與內文
     */
    public LoggingAccountMailer(AccountMailContent content) {
        this.content = content;
        log.warn("Account mails are written to the log instead of being sent (account.mail.log-links=true); "
                + "anyone who can read the log can reset passwords. Use this for development only");
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public void send(AccountMail mail) {
        log.warn("Account mail to {}: {}\n{}", mail.to(), content.subject(mail), content.text(mail));
    }
}
