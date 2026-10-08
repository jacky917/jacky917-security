package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration of the jacky917-security authorization server.
 * <p>
 * jacky917-security Authorization Server 的自動配置。
 * <p>
 * The whole configuration is disabled when
 * {@code jacky917.security.authorization-server.enabled=false}. It runs
 * after the data source is created, because every component stores its
 * state in the authorization server's own database.
 * <p>
 * 設定 {@code jacky917.security.authorization-server.enabled=false} 時整個
 * 配置停用。此配置在資料來源建立之後執行，因為所有元件都把狀態存放在
 * Authorization Server 專屬的資料庫中。
 *
 * @author Jacky
 * @since 2.1.0
 */
// 以字串指定 Spring Boot 的安全性與 Authorization Server 自動配置：本配置的 filter chain、
// JWKSource、JwtEncoder、UserDetailsService 等必須先註冊，Spring Boot 的預設值才會讓位
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, DataSourceTransactionManagerAutoConfiguration.class}, beforeName = {
        "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration"
})
@ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(AuthorizationServerProperties.class)
@Import({AuthorizationServerDatabaseConfiguration.class, AuthorizationServerKeysConfiguration.class,
        AuthorizationServerClientsConfiguration.class, AuthorizationServerUsersConfiguration.class,
        AuthorizationServerSecurityConfiguration.class, AuthorizationServerAdminApiConfiguration.class,
        AuthorizationServerMaintenanceConfiguration.class})
public class AuthorizationServerAutoConfiguration {
}
