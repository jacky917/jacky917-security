package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.account.AccountLinks;
import jacky917.security.authorizationserver.account.AccountMailContent;
import jacky917.security.authorizationserver.account.AccountMailer;
import jacky917.security.authorizationserver.account.ActionTokenService;
import jacky917.security.authorizationserver.account.LoggingAccountMailer;
import jacky917.security.authorizationserver.account.SpringAccountMailer;
import jacky917.security.authorizationserver.account.UnavailableAccountMailer;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;

/**
 * Account self-service support: the account mails and their one-time
 * tokens (phase 3 and 4 design §5).
 * <p>
 * 帳號自助功能的基礎：帳號信件與其一次性 token（第 3、4 階段設計 §5）。
 * <p>
 * The mailer is chosen in this order (D26): the application's own
 * {@link AccountMailer} bean; Spring's {@code JavaMailSender} when the
 * application has one ({@code account.mail.from} is then required); the log
 * when {@code account.mail.log-links=true}; otherwise none, and the features
 * that need mails are not offered.
 * <p>
 * mailer 依以下順序選擇（D26）：應用程式自己的 {@code AccountMailer} Bean；
 * 應用程式有 Spring 的 {@code JavaMailSender} 時以它寄信（此時
 * {@code account.mail.from} 為必填）；{@code account.mail.log-links=true} 時
 * 寫入日誌；否則沒有寄信方式，需要寄信的功能不提供。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerAccountConfiguration {

    @Bean
    @ConditionalOnMissingBean
    AccountMailContent accountMailContent(AuthorizationServerProperties properties) {
        return new AccountMailContent(properties.getBranding().getProductName());
    }

    @Bean
    @ConditionalOnMissingBean
    AccountMailer accountMailer(AuthorizationServerProperties properties, AccountMailContent content) {
        return withoutMailSender(properties, content);
    }

    @Bean
    @ConditionalOnMissingBean
    AccountLinks accountLinks(AuthorizationServerProperties properties) {
        return new AccountLinks(properties.getIssuer());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    ActionTokenService actionTokenService(JdbcClient jdbcClient, PlatformTransactionManager transactionManager,
                                          Clock clock) {
        return new ActionTokenService(jdbcClient, new TransactionTemplate(transactionManager), clock);
    }

    static AccountMailer withoutMailSender(AuthorizationServerProperties properties, AccountMailContent content) {
        return properties.getAccount().getMail().isLogLinks() ? new LoggingAccountMailer(content)
                : new UnavailableAccountMailer();
    }

    /**
     * Uses Spring's {@code JavaMailSender} when the mail classes are present
     * and the application has one. Member classes are processed before the
     * outer {@code @Bean} methods, so this bean wins over the fallback.
     * <p>
     * 有郵件類別且應用程式有 {@code JavaMailSender} 時使用它。成員類別會先於外層
     * 的 {@code @Bean} 方法處理，因此此 Bean 優先於預設的 Bean。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(JavaMailSender.class)
    static class SpringMail {

        @Bean
        @ConditionalOnMissingBean
        AccountMailer accountMailer(AuthorizationServerProperties properties, AccountMailContent content,
                                    ObjectProvider<JavaMailSender> mailSender) {
            JavaMailSender sender = mailSender.getIfAvailable();
            if (sender == null) {
                return withoutMailSender(properties, content);
            }
            String from = properties.getAccount().getMail().getFrom();
            if (from == null || from.isBlank()) {
                throw new IllegalStateException(AuthorizationServerProperties.PREFIX + ".account.mail.from is "
                        + "required to send account mails with spring.mail.*");
            }
            return new SpringAccountMailer(sender, content, from);
        }
    }
}
