package jacky917.security.authorizationserver.account;

/**
 * The mailer used when the application has no way to send mails: the
 * features that need mails are not offered.
 * <p>
 * 應用程式沒有寄信方式時使用的 mailer：需要寄信的功能不提供。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class UnavailableAccountMailer implements AccountMailer {

    @Override
    public boolean isAvailable() {
        return false;
    }

    /**
     * Always refuses, because no mail can be sent.
     * <p>
     * 一律拒絕，因為無法寄信。
     *
     * @param mail  the mail
     *              <br>信件
     * @throws IllegalStateException always
     *         <br>一律拋出
     */
    @Override
    public void send(AccountMail mail) {
        throw new IllegalStateException("No way to send account mails: add spring-boot-starter-mail and set "
                + "spring.mail.* and account.mail.from");
    }
}
