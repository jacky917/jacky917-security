package jacky917.security.authorizationserver.account;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Duration;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * 帳號信件的內容（繁中、英文）與各種 mailer。
 */
@DisplayName("AccountMail、AccountMailContent、AccountMailer")
class AccountMailTest {

    private final AccountMailContent content = new AccountMailContent("Acme");

    @Test
    @DisplayName("重設密碼信：主旨與內文帶有產品名稱、使用者名稱、連結與有效分鐘數")
    void passwordReset() {
        AccountMail mail = new AccountMail(AccountMail.Type.PASSWORD_RESET, "alice@example.com", Locale.ENGLISH,
                "Alice", "https://auth.example.com/jacky917/password/reset?token=t", Duration.ofHours(1));
        assertThat(content.subject(mail)).isEqualTo("Reset your Acme password");
        assertThat(content.text(mail)).contains("Hello Alice").contains("?token=t").contains("60 minutes");
    }

    @Test
    @DisplayName("繁體中文；沒有顯示名稱時以 Email 稱呼")
    void traditionalChinese() {
        AccountMail mail = new AccountMail(AccountMail.Type.EMAIL_VERIFICATION, "bob@example.com",
                Locale.TRADITIONAL_CHINESE, null, "https://auth.example.com/v", Duration.ofHours(24));
        assertThat(content.subject(mail)).isEqualTo("確認您的 Acme Email");
        assertThat(content.text(mail)).startsWith("bob@example.com 您好").contains("1,440 分鐘");
    }

    @Test
    @DisplayName("每一種信件都有英文與繁中的主旨與內文")
    void everyTypeHasTexts() {
        for (AccountMail.Type type : AccountMail.Type.values()) {
            for (Locale locale : new Locale[]{Locale.ENGLISH, Locale.TRADITIONAL_CHINESE}) {
                AccountMail mail = new AccountMail(type, "a@example.com", locale, "A", "https://x", Duration.ofHours(1));
                assertThat(content.subject(mail)).isNotBlank().doesNotContain("{");
                assertThat(content.text(mail)).contains("https://x").doesNotContain("{");
            }
        }
    }

    @Test
    @DisplayName("SpringAccountMailer：以 JavaMailSender 寄出純文字信件")
    void springMailer() {
        JavaMailSender sender = mock(JavaMailSender.class);
        AccountMailer mailer = new SpringAccountMailer(sender, content, "no-reply@example.com");
        mailer.send(new AccountMail(AccountMail.Type.PASSWORD_CHANGED, "alice@example.com", Locale.ENGLISH, "Alice",
                "https://x", null));
        ArgumentCaptor<SimpleMailMessage> message = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(sender).send(message.capture());
        assertThat(message.getValue().getFrom()).isEqualTo("no-reply@example.com");
        assertThat(message.getValue().getTo()).containsExactly("alice@example.com");
        assertThat(message.getValue().getSubject()).isEqualTo("Your Acme password was changed");
        assertThat(mailer.isAvailable()).isTrue();
    }

    @Test
    @DisplayName("UnavailableAccountMailer：不可用，寄信時拋出例外")
    void unavailableMailer() {
        AccountMailer mailer = new UnavailableAccountMailer();
        assertThat(mailer.isAvailable()).isFalse();
        assertThatThrownBy(() -> mailer.send(new AccountMail(AccountMail.Type.PASSWORD_RESET, "a@example.com",
                Locale.ENGLISH, null, null, null))).isInstanceOf(IllegalStateException.class);
    }
}
