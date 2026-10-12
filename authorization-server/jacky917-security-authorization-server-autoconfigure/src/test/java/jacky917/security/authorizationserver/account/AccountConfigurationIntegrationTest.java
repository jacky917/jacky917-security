package jacky917.security.authorizationserver.account;

import jacky917.security.authorizationserver.support.MutableClock;
import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * 寄信方式的選擇（D26）、註冊對寄信的要求與一次性 token（D28），在 SQLite 與 PostgreSQL 上執行。
 */
@DisplayName("帳號信件的設定與一次性 token（SQLite／PostgreSQL）")
class AccountConfigurationIntegrationTest {

    @Test
    @DisplayName("沒有 JavaMailSender：不可寄信；log-links=true 時寫入日誌")
    void withoutMailSender() {
        TestDatabases.runner(TestDatabases.SQLITE).run(context ->
                assertThat(context).getBean(AccountMailer.class).isInstanceOf(UnavailableAccountMailer.class));
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("jacky917.security.authorization-server.account.mail.log-links=true")
                .run(context -> assertThat(context).getBean(AccountMailer.class)
                        .isInstanceOf(LoggingAccountMailer.class));
    }

    @Test
    @DisplayName("有 JavaMailSender：以它寄信；沒有設定 account.mail.from 時啟動失敗")
    void withMailSender() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withBean(JavaMailSender.class, () -> mock(JavaMailSender.class))
                .withPropertyValues("jacky917.security.authorization-server.account.mail.from=no-reply@example.com")
                .run(context -> assertThat(context).getBean(AccountMailer.class)
                        .isInstanceOf(SpringAccountMailer.class));
        TestDatabases.runner(TestDatabases.SQLITE)
                .withBean(JavaMailSender.class, () -> mock(JavaMailSender.class))
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasStackTraceContaining("account.mail.from is required"));
    }

    @Test
    @DisplayName("背景寄信的 executor 不是 Bean：應用程式仍有 Spring Boot 的 applicationTaskExecutor")
    void keepsTheApplicationTaskExecutor() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withConfiguration(AutoConfigurations.of(TaskExecutionAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasBean("applicationTaskExecutor");
                    assertThat(context).hasSingleBean(AccountMailDispatcher.class);
                });
    }

    @Test
    @DisplayName("應用程式自己的 AccountMailer 優先")
    void applicationMailerWins() {
        AccountMailer own = new UnavailableAccountMailer();
        TestDatabases.runner(TestDatabases.SQLITE)
                .withBean(JavaMailSender.class, () -> mock(JavaMailSender.class))
                .withBean("myMailer", AccountMailer.class, () -> own)
                .run(context -> assertThat(context).getBean(AccountMailer.class).isSameAs(own));
    }

    @Test
    @DisplayName("開啟註冊卻無法寄信：啟動失敗，訊息說明如何設定（T-ACCT-08）")
    void registrationNeedsMail() {
        assertThatThrownBy(() -> new RegistrationService(mock(UserAccountService.class), mock(JdbcClient.class),
                mock(PasswordEncoder.class), mock(ActionTokenService.class),
                new AccountMailDispatcher(new UnavailableAccountMailer(), Runnable::run, mock(ApplicationEventPublisher.class)),
                mock(AccountLinks.class), mock(ApplicationEventPublisher.class), mock(TransactionOperations.class),
                Duration.ofHours(24), Duration.ofHours(1), Clock.systemUTC()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("account.registration.enabled")
                .hasMessageContaining("spring.mail.host");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {TestDatabases.SQLITE, TestDatabases.POSTGRESQL})
    @DisplayName("一次性 token：60 秒內不重複發出；新 token 取代舊的；只能使用一次；到期後無效；用途必須相符")
    void actionTokens(String vendor) {
        MutableClock clock = new MutableClock();
        TestDatabases.runner(vendor).withBean(Clock.class, () -> clock).run(context -> {
            ActionTokenService tokens = context.getBean(ActionTokenService.class);
            String userId = context.getBean(UserAccountService.class)
                    .createUser(new NewUser("token-user", null, false, null, null, Set.of())).id();

            String first = tokens.issue(userId, ActionTokenService.Purpose.PASSWORD_RESET, Duration.ofHours(1))
                    .orElseThrow();
            assertThat(tokens.issue(userId, ActionTokenService.Purpose.PASSWORD_RESET, Duration.ofHours(1)))
                    .as("60 秒內不再發出").isEmpty();
            assertThat(tokens.issue(userId, ActionTokenService.Purpose.EMAIL_VERIFY, Duration.ofHours(1)))
                    .as("不同用途各自計算").isPresent();
            assertThat(tokens.find(first, ActionTokenService.Purpose.PASSWORD_RESET)).contains(userId);
            assertThat(tokens.find(first, ActionTokenService.Purpose.EMAIL_VERIFY)).as("用途不符").isEmpty();

            clock.advance(Duration.ofSeconds(61));
            String second = tokens.issue(userId, ActionTokenService.Purpose.PASSWORD_RESET, Duration.ofHours(1))
                    .orElseThrow();
            assertThat(tokens.find(first, ActionTokenService.Purpose.PASSWORD_RESET)).as("被新的取代").isEmpty();
            assertThat(tokens.consume(second, ActionTokenService.Purpose.PASSWORD_RESET)).contains(userId);
            assertThat(tokens.consume(second, ActionTokenService.Purpose.PASSWORD_RESET)).as("只能使用一次").isEmpty();

            clock.advance(Duration.ofSeconds(61));
            String third = tokens.issue(userId, ActionTokenService.Purpose.PASSWORD_RESET, Duration.ofHours(1))
                    .orElseThrow();
            clock.advance(Duration.ofHours(2));
            assertThat(tokens.find(third, ActionTokenService.Purpose.PASSWORD_RESET)).as("已到期").isEmpty();
            assertThat(tokens.consume("not-a-token", ActionTokenService.Purpose.PASSWORD_RESET))
                    .isEqualTo(Optional.empty());
        });
    }
}
