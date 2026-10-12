package jacky917.security.authorizationserver.account;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Sends account mails as plain text through Spring's {@code JavaMailSender}
 * ({@code spring-boot-starter-mail} with {@code spring.mail.*}).
 * <p>
 * 透過 Spring 的 {@code JavaMailSender}（{@code spring-boot-starter-mail} 與
 * {@code spring.mail.*}）以純文字寄出帳號信件。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SpringAccountMailer implements AccountMailer {

    private final JavaMailSender sender;
    private final AccountMailContent content;
    private final String from;

    /**
     * Creates the mailer.
     * <p>
     * 建立 mailer。
     *
     * @param sender   sends the messages
     *                 <br>寄出訊息
     * @param content  writes the subject and text
     *                 <br>產生主旨與內文
     * @param from     the sender address, {@code account.mail.from}
     *                 <br>寄件者地址，即 {@code account.mail.from}
     */
    public SpringAccountMailer(JavaMailSender sender, AccountMailContent content, String from) {
        this.sender = sender;
        this.content = content;
        this.from = from;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public void send(AccountMail mail) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(mail.to());
        message.setSubject(content.subject(mail));
        message.setText(content.text(mail));
        sender.send(message);
    }
}
