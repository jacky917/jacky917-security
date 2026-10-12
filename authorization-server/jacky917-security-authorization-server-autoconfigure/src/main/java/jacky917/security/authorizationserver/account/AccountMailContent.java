package jacky917.security.authorizationserver.account;

import org.springframework.context.MessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Locale;

/**
 * The subject and text of an account mail, from the starter's message
 * bundle ({@code mail.*} keys of
 * {@code jacky917/authorization-server-messages}).
 * <p>
 * 帳號信件的主旨與內文，取自 starter 的訊息檔
 * （{@code jacky917/authorization-server-messages} 的 {@code mail.*} key）。
 * <p>
 * The arguments of each message are {@code {0}} the product name,
 * {@code {1}} the user's name, {@code {2}} the link and {@code {3}} how many
 * minutes the link works. An application can replace the texts by putting a
 * bundle with the same name earlier on the classpath.
 * <p>
 * 訊息的參數為 {@code {0}} 產品名稱、{@code {1}} 使用者名稱、{@code {2}} 連結、
 * {@code {3}} 連結的有效分鐘數。應用程式可以在 classpath 較前面放一份同名的
 * 訊息檔取代這些文字。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AccountMailContent {

    private final MessageSource messages;
    private final String productName;

    /**
     * Creates the content for the given product.
     * <p>
     * 為指定的產品建立信件內容。
     *
     * @param productName  the product name shown in the mails
     *                     <br>信件中顯示的產品名稱
     */
    public AccountMailContent(String productName) {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("jacky917/authorization-server-messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        this.messages = source;
        this.productName = productName;
    }

    /**
     * Returns the subject of a mail.
     * <p>
     * 回傳信件的主旨。
     *
     * @param mail  the mail
     *              <br>信件
     * @return the subject
     *         <br>主旨
     */
    public String subject(AccountMail mail) {
        return message(mail, "subject");
    }

    /**
     * Returns the plain text of a mail.
     * <p>
     * 回傳信件的純文字內文。
     *
     * @param mail  the mail
     *              <br>信件
     * @return the text
     *         <br>內文
     */
    public String text(AccountMail mail) {
        return message(mail, "text");
    }

    private String message(AccountMail mail, String part) {
        String key = "mail." + mail.type().name().toLowerCase(Locale.ROOT).replace('_', '-') + "." + part;
        String name = mail.displayName() == null || mail.displayName().isBlank() ? mail.to() : mail.displayName();
        long minutes = mail.validFor() == null ? 0 : mail.validFor().toMinutes();
        return messages.getMessage(key, new Object[]{productName, name, mail.link(),
                minutes}, mail.locale());
    }
}
