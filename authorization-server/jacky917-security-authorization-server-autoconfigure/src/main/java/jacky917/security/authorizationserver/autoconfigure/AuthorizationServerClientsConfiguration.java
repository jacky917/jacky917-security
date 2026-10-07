package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.client.ActiveClientRegisteredClientRepository;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.client.ClientRegistrationSynchronizer;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.Map;

/**
 * Client configuration: storage, suspension, secrets, and the clients
 * declared in the configuration.
 * <p>
 * Client 配置：儲存、停權、secret，以及設定中宣告的 client。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerClientsConfiguration {

    /**
     * Hashes passwords and client secrets with BCrypt, in the
     * {@code {bcrypt}} format so the algorithm can change later (D21).
     * <p>
     * 以 BCrypt 雜湊密碼與 client secret，使用 {@code {bcrypt}} 格式，日後可
     * 更換演算法（D21）。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @return the password encoder
     *         <br>密碼編碼器
     */
    @Bean
    @ConditionalOnMissingBean
    PasswordEncoder passwordEncoder(AuthorizationServerProperties properties) {
        return new DelegatingPasswordEncoder("bcrypt",
                Map.of("bcrypt", new BCryptPasswordEncoder(properties.getPassword().getBcryptStrength())));
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    ClientProfileRepository clientProfileRepository(JdbcClient jdbcClient) {
        return new ClientProfileRepository(jdbcClient);
    }

    /**
     * The official JDBC repository, hiding suspended clients.
     * <p>
     * 官方 JDBC repository，並隱藏已停權的 client。
     *
     * @param jdbcOperations  the JDBC operations of the authorization server database
     *                        <br>Authorization Server 資料庫的 JDBC operations
     * @param profiles        the client profiles
     *                        <br>client 資料
     * @return the client repository
     *         <br>client repository
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations,
                                                          ClientProfileRepository profiles) {
        return new ActiveClientRegisteredClientRepository(new JdbcRegisteredClientRepository(jdbcOperations), profiles);
    }

    /**
     * Creates or updates the configured clients at startup.
     * <p>
     * 啟動時建立或更新設定中的 client。
     * <p>
     * It uses the unfiltered JDBC repository: through the filtered one a
     * suspended client would look missing and be inserted a second time.
     * <p>
     * 使用未過濾的 JDBC repository：透過過濾後的 repository，已停權的 client
     * 看起來不存在，會被重複新增。
     *
     * @return the initializer
     *         <br>初始化器
     */
    @Bean
    @DependsOnDatabaseInitialization
    InitializingBean clientRegistrationInitializer(JdbcOperations jdbcOperations, ClientProfileRepository profiles,
                                                   PasswordEncoder passwordEncoder,
                                                   AuthorizationServerProperties properties,
                                                   PlatformTransactionManager transactionManager, Clock clock) {
        ClientRegistrationSynchronizer synchronizer = new ClientRegistrationSynchronizer(
                new JdbcRegisteredClientRepository(jdbcOperations), profiles, passwordEncoder, properties,
                new TransactionTemplate(transactionManager), clock);
        return synchronizer::synchronize;
    }
}
