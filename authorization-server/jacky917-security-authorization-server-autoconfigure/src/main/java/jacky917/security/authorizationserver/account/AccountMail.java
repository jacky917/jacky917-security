package jacky917.security.authorizationserver.account;

import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/**
 * An email about a user's account, sent through {@link AccountMailer}.
 * <p>
 * 關於使用者帳號的信件，由 {@code AccountMailer} 寄出。
 *
 * @param type         what the mail is about
 *                     <br>信件的用途
 * @param to           the recipient address
 *                     <br>收件者地址
 * @param locale       the language to write it in
 *                     <br>信件使用的語言
 * @param displayName  the user's name for the greeting, or {@code null}
 *                     <br>問候語中使用者的名稱，或 {@code null}
 * @param link         the link the user should open, or {@code null} for a
 *                     notice without a link
 *                     <br>使用者應開啟的連結；沒有連結的通知為 {@code null}
 * @param validFor     how long the link works, or {@code null}
 *                     <br>連結的有效期，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record AccountMail(Type type, String to, Locale locale, @Nullable String displayName, @Nullable String link,
                          @Nullable Duration validFor) {

    /**
     * Creates the mail.
     * <p>
     * 建立信件。
     */
    public AccountMail {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(to, "to");
        Objects.requireNonNull(locale, "locale");
    }

    /**
     * What an account mail is about.
     * <p>
     * 帳號信件的用途。
     */
    public enum Type {

        /**
         * Asks the user to confirm their email address after registering.
         * <p>
         * 註冊後請使用者確認 Email。
         */
        EMAIL_VERIFICATION,

        /**
         * Lets the user set a new password.
         * <p>
         * 讓使用者設定新密碼。
         */
        PASSWORD_RESET,

        /**
         * Tells the owner of an address that someone tried to register it
         * again, with a link to reset the password.
         * <p>
         * 通知地址的擁有者有人再次以它註冊，並附上重設密碼的連結。
         */
        ACCOUNT_EXISTS,

        /**
         * Tells the user that their password was changed.
         * <p>
         * 通知使用者密碼已變更。
         */
        PASSWORD_CHANGED
    }
}
