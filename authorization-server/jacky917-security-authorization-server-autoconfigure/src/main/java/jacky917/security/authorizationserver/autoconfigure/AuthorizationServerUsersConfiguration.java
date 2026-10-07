package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.user.BootstrapAdminInitializer;
import jacky917.security.authorizationserver.user.Jacky917UserDetailsService;
import jacky917.security.authorizationserver.user.JdbcUserAccountService;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;

/**
 * User configuration: accounts, password login, and the first
 * administrator.
 * <p>
 * 使用者配置：帳號、帳號密碼登入與第一位管理員。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerUsersConfiguration {

    @Bean
    @ConditionalOnMissingBean
    PasswordPolicy passwordPolicy(AuthorizationServerProperties properties) {
        return new PasswordPolicy(properties.getPassword().getMinLength());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    UserAccountService userAccountService(JdbcClient jdbcClient, PasswordEncoder passwordEncoder,
                                          PasswordPolicy passwordPolicy, Clock clock) {
        return new JdbcUserAccountService(jdbcClient, passwordEncoder, passwordPolicy, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    UserDetailsService userDetailsService(UserAccountService users, Clock clock) {
        return new Jacky917UserDetailsService(users, clock);
    }

    @Bean
    @DependsOnDatabaseInitialization
    InitializingBean bootstrapAdminInitializer(AuthorizationServerProperties properties, UserAccountService users,
                                               JdbcClient jdbcClient, PlatformTransactionManager transactionManager) {
        return new BootstrapAdminInitializer(properties.getBootstrapAdmin(), users, jdbcClient,
                new TransactionTemplate(transactionManager))::initialize;
    }
}
