package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.authentication.LoginSuccessHandler;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.time.Clock;

/**
 * Web security of the authorization server (detailed design §3): the
 * OAuth 2.0 / OIDC endpoints and the login pages.
 * <p>
 * Authorization Server 的 Web 安全設定（詳細設計 §3）：OAuth 2.0／OIDC 端點與
 * 登入頁。
 * <ul>
 *   <li>Order 1 handles only Spring Authorization Server's endpoints
 *       ({@code /oauth2/**}, {@code /.well-known/**}, {@code /userinfo},
 *       {@code /connect/**}); a browser without a login is sent to
 *       {@code /login}.
 *       <br>Order 1 只處理 Spring Authorization Server 的端點；未登入的瀏覽器
 *       會被導向 {@code /login}。</li>
 *   <li>Order 3 handles everything else: the login form with CSRF
 *       protection, a new session id after login, and headers that forbid
 *       framing.
 *       <br>Order 3 處理其餘請求：有 CSRF 保護的登入表單、登入後更換 Session
 *       ID，以及禁止被嵌入 iframe 的標頭。</li>
 * </ul>
 * Each chain backs off when the application defines a bean with the same
 * name.
 * <p>
 * 應用程式定義同名的 bean 時，對應的 filter chain 不會建立。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class AuthorizationServerSecurityConfiguration {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'; form-action 'self'";

    @Bean
    @Order(1)
    @ConditionalOnMissingBean(name = "authorizationServerSecurityFilterChain")
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 已查證：Spring Security 7.1.1 的 OAuth2AuthorizationServerConfigurer 只有公開建構子
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // /userinfo 以 Access Token 存取
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    @Bean
    @Order(3)
    @ConditionalOnMissingBean(name = "loginSecurityFilterChain")
    SecurityFilterChain loginSecurityFilterChain(HttpSecurity http, LoginSuccessHandler loginSuccessHandler)
            throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/error", "/jacky917/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(loginSuccessHandler)
                        // 所有失敗原因導向同一個網址，頁面顯示相同的訊息（詳細設計 §7.2）
                        .failureUrl("/login?error"))
                .sessionManagement(session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY)));
        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    AuthorizationServerSettings authorizationServerSettings(AuthorizationServerProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.getIssuer().toString()).build();
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, clients);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
                                                                  RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, clients);
    }

    /**
     * Validates access tokens at {@code /userinfo} with the published keys.
     * <p>
     * 以公開的金鑰驗證 {@code /userinfo} 收到的 Access Token。
     *
     * @param jwkSource  the published keys
     *                   <br>公開的金鑰
     * @return the decoder
     *         <br>decoder
     */
    @Bean
    @ConditionalOnMissingBean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AuthSessionService authSessionService(JdbcClient jdbcClient, AuthorizationServerProperties properties, Clock clock) {
        return new AuthSessionService(jdbcClient, properties.getToken().getSessionMaxAge(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginSuccessHandler loginSuccessHandler(AuthSessionService sessions, UserAccountService users, Clock clock) {
        return new LoginSuccessHandler(sessions, users, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginController jacky917LoginController(AuthorizationServerProperties properties) {
        return new LoginController(properties);
    }
}
