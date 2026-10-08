package jacky917.security.authorizationserver.account;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;

import java.time.Duration;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * 背景寄信：失敗時依原因發布事件，不拋出例外。
 */
class AccountMailDispatcherTest {

    private static final AccountMail MAIL = new AccountMail(AccountMail.Type.PASSWORD_RESET, "a@example.com",
            Locale.ENGLISH, null, "https://x", Duration.ofHours(1));

    private final AccountMailer mailer = mock(AccountMailer.class);
    private final ApplicationEventPublisher events = mock(ApplicationEventPublisher.class);
    private final AccountMailDispatcher dispatcher = new AccountMailDispatcher(mailer, Runnable::run, events);

    @Test
    @DisplayName("寄出成功：不發布事件")
    void sends() {
        dispatcher.send(MAIL, "u1");
        verify(mailer).send(MAIL);
        verify(events, never()).publishEvent(org.mockito.ArgumentMatchers.any(Object.class));
    }

    @Test
    @DisplayName("郵件伺服器拒絕登入：authentication；其他郵件錯誤：delivery；其他例外：internal")
    void classifiesFailures() {
        assertThat(failWith(new MailAuthenticationException("bad login"))).isEqualTo("authentication");
        assertThat(failWith(new MailSendException("down"))).isEqualTo("delivery");
        assertThat(failWith(new IllegalStateException("missing text"))).isEqualTo("internal");
    }

    @Test
    @DisplayName("交給 executor 執行：呼叫端不等待寄信")
    void runsInTheExecutor() {
        java.util.List<Runnable> queued = new java.util.ArrayList<>();
        new AccountMailDispatcher(mailer, queued::add, events).send(MAIL, "u1");
        verify(mailer, never()).send(MAIL);
        queued.forEach(Runnable::run);
        verify(mailer).send(MAIL);
    }

    private String failWith(RuntimeException failure) {
        AccountMailer failing = mock(AccountMailer.class);
        doThrow(failure).when(failing).send(MAIL);
        ApplicationEventPublisher published = mock(ApplicationEventPublisher.class);
        new AccountMailDispatcher(failing, Runnable::run, published).send(MAIL, "u1");
        ArgumentCaptor<AccountMailFailedEvent> event = ArgumentCaptor.forClass(AccountMailFailedEvent.class);
        verify(published).publishEvent(event.capture());
        assertThat(event.getValue().type()).isEqualTo(AccountMail.Type.PASSWORD_RESET);
        return event.getValue().reason();
    }
}
