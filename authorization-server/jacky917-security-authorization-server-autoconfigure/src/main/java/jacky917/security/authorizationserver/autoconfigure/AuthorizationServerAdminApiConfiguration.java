package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.admin.AdminApiExceptionHandler;
import jacky917.security.authorizationserver.admin.AdminAuditService;
import jacky917.security.authorizationserver.admin.AdminJwtAuthenticationConverter;
import jacky917.security.authorizationserver.admin.AuditAdminController;
import jacky917.security.authorizationserver.admin.RoleAdminController;
import jacky917.security.authorizationserver.admin.RoleAdminService;
import jacky917.security.authorizationserver.admin.UserAdminController;
import jacky917.security.authorizationserver.admin.UserAdminService;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.Jacky917LogoutHandler;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.Collection;

/**
 * The administration API under {@code /admin/api} (phase 3 and 4 design
 * §4).
 * <p>
 * {@code /admin/api} 之下的管理 API（第 3、4 階段設計 §4）。
 * <p>
 * An Order 2 filter chain accepts only bearer access tokens issued by this
 * authorization server whose {@code aud} contains
 * {@code admin-api.audience}, and authorizes each path with an {@code as:}
 * permission. It keeps no session and needs no CSRF token.
 * {@code admin-api.enabled=false} removes the API.
 * <p>
 * Order 2 的 filter chain 只接受本 Authorization Server 簽發、且 {@code aud}
 * 包含 {@code admin-api.audience} 的 Bearer Access Token，並以 {@code as:}
 * 權限授權每個路徑；不保留 Session，也不需要 CSRF token。設定
 * {@code admin-api.enabled=false} 即移除此 API。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX + ".admin-api", name = "enabled",
        havingValue = "true", matchIfMissing = true)
class AuthorizationServerAdminApiConfiguration {

    static final String PATH = "/admin/api";

    @Bean
    @Order(2)
    @ConditionalOnMissingBean(name = "adminApiSecurityFilterChain")
    SecurityFilterChain adminApiSecurityFilterChain(HttpSecurity http, JWKSource<SecurityContext> jwkSource,
                                                    AuthorizationServerProperties properties) throws Exception {
        JwtDecoder decoder = adminJwtDecoder(jwkSource, properties.getIssuer().toString(),
                properties.getAdminApi().effectiveAudience(properties.getToken()));
        http.securityMatcher(PATH + "/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, PATH + "/users/*/sessions", PATH + "/sessions/**")
                        .hasAuthority("as:user:read")
                        .requestMatchers(PATH + "/users/*/sessions", PATH + "/sessions/**").hasAuthority("as:session:revoke")
                        .requestMatchers(HttpMethod.GET, PATH + "/users/**").hasAuthority("as:user:read")
                        .requestMatchers(PATH + "/users/**").hasAuthority("as:user:write")
                        .requestMatchers(HttpMethod.GET, PATH + "/roles/**", PATH + "/permissions/**")
                        .hasAuthority("as:role:read")
                        .requestMatchers(PATH + "/roles/**", PATH + "/permissions/**").hasAuthority("as:role:write")
                        .requestMatchers(HttpMethod.GET, PATH + "/clients/**", PATH + "/scopes/**",
                                PATH + "/api-resources/**").hasAuthority("as:client:read")
                        .requestMatchers(PATH + "/clients/**", PATH + "/scopes/**", PATH + "/api-resources/**")
                        .hasAuthority("as:client:write")
                        .requestMatchers(HttpMethod.GET, PATH + "/audit/**").hasAuthority("as:audit:read")
                        .anyRequest().denyAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 只接受 Bearer token，沒有 Cookie 可被利用
                .csrf(csrf -> csrf.disable())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.decoder(decoder)
                        .jwtAuthenticationConverter(new AdminJwtAuthenticationConverter())));
        return http.build();
    }

    /**
     * Validates admin tokens: signed by this server's keys, issued by it,
     * not expired, and meant for the administration API.
     * <p>
     * 驗證管理用的 token：以本伺服器的金鑰簽章、由本伺服器簽發、未過期，且
     * 對象是管理 API。
     */
    static JwtDecoder adminJwtDecoder(JWKSource<SecurityContext> jwkSource, String issuer, String audience) {
        // 另建一個 decoder：不影響 /userinfo 使用的 JwtDecoder Bean
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<Collection<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(audience))));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AdminAuditService adminAuditService(JdbcClient jdbcClient, Clock clock) {
        return new AdminAuditService(jdbcClient, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    AdminApiExceptionHandler jacky917AdminApiExceptionHandler() {
        return new AdminApiExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    AuditAdminController jacky917AuditAdminController(JdbcClient jdbcClient) {
        return new AuditAdminController(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    UserAdminService userAdminService(JdbcClient jdbcClient, UserAccountService users, AuthSessionService sessions,
                                      PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                                      AdminAuditService audit, PlatformTransactionManager transactionManager,
                                      Clock clock) {
        return new UserAdminService(jdbcClient, users, sessions, passwordEncoder, passwordPolicy, audit,
                new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    UserAdminController jacky917UserAdminController(UserAdminService users, AuthSessionService sessions,
                                                    Jacky917LogoutHandler logoutHandler, AdminAuditService audit) {
        return new UserAdminController(users, sessions, logoutHandler, audit);
    }

    @Bean
    @ConditionalOnMissingBean
    RoleAdminService roleAdminService(JdbcClient jdbcClient, AdminAuditService audit,
                                      PlatformTransactionManager transactionManager, Clock clock) {
        return new RoleAdminService(jdbcClient, audit, new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    RoleAdminController jacky917RoleAdminController(RoleAdminService roles) {
        return new RoleAdminController(roles);
    }
}
