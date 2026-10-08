package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.audit.JdbcLoginAuditListener;
import jacky917.security.authorizationserver.audit.LoginAuditRepository;
import jacky917.security.authorizationserver.authentication.LoginAttemptGuard;
import jacky917.security.authorizationserver.authentication.LoginFailureHandler;
import jacky917.security.authorizationserver.authentication.LoginSuccessHandler;
import jacky917.security.authorizationserver.authentication.PrincipalNormalizer;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.FederatedUserInfoMapper;
import jacky917.security.authorizationserver.federation.OidcFederatedUserInfoMapper;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.database.AuthorizationServerDialect;
import jacky917.security.authorizationserver.refresh.RefreshTokenHistoryRepository;
import jacky917.security.authorizationserver.refresh.RefreshTokenReuseDetector;
import jacky917.security.authorizationserver.token.AudienceResolver;
import jacky917.security.authorizationserver.token.AuthorityResolver;
import jacky917.security.authorizationserver.token.ConfiguredAudienceResolver;
import jacky917.security.authorizationserver.token.DefaultAuthorityResolver;
import jacky917.security.authorizationserver.token.Jacky917TokenCustomizer;
import jacky917.security.authorizationserver.token.TokenClaimsContributor;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.Jacky917LogoutHandler;
import jacky917.security.authorizationserver.session.LoginSessionValidationFilter;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.session.SessionLinkingAuthorizationService;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.AccountController;
import jacky917.security.authorizationserver.web.LoginController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.ZoneId;

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
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, AuthSessionService sessions,
                                                              RefreshTokenReuseDetector reuseDetector,
                                                              Jacky917LogoutHandler logoutHandler, Clock clock)
            throws Exception {
        // RP-Initiated Logout 撤銷整個登入 Session，而不只是結束瀏覽器的登入（詳細設計 §5.5）
        OidcLogoutAuthenticationSuccessHandler logoutResponse = new OidcLogoutAuthenticationSuccessHandler();
        logoutResponse.setLogoutHandler(logoutHandler);
        // 已查證：Spring Security 7.1.1 的 OAuth2AuthorizationServerConfigurer 只有公開建構子
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server
                        .oidc(oidc -> oidc.logoutEndpoint(logout -> logout.logoutResponseHandler(logoutResponse)))
                        // 刷新改經過重用偵測（詳細設計 §5.4）
                        .tokenEndpoint(token -> token.authenticationProviders(reuseDetector::install)))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // /userinfo 以 Access Token 存取
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 登入 Session 已失效時結束瀏覽器登入，授權請求因此回到登入頁，而不是錯誤頁
                .addFilterBefore(new LoginSessionValidationFilter(sessions, clock), AuthorizationFilter.class);
        return http.build();
    }

    @Bean
    @Order(3)
    @ConditionalOnMissingBean(name = "loginSecurityFilterChain")
    SecurityFilterChain loginSecurityFilterChain(HttpSecurity http, LoginSuccessHandler loginSuccessHandler,
                                                 ObjectProvider<ClientRegistrationRepository> clientRegistrations,
                                                 ObjectProvider<FederatedLoginSuccessHandler> federatedLoginSuccessHandler,
                                                 LoginFailureHandler loginFailureHandler,
                                                 LoginAuditRepository loginAudits, ApplicationEventPublisher events,
                                                 AuthorizationServerProperties properties,
                                                 Jacky917LogoutHandler logoutHandler, AuthSessionService sessions,
                                                 Clock clock)
            throws Exception {
        // 有設定第三方登入（spring.security.oauth2.client.registration.*）時才啟用
        if (clientRegistrations.getIfAvailable() != null) {
            http.oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .successHandler(federatedLoginSuccessHandler.getObject())
                    .failureUrl("/login?error=federation"));
        }
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(LoginController.SIGNED_IN_PATH, AccountController.ACCOUNT_PATH,
                                AccountController.ACCOUNT_PATH + "/**").authenticated()
                        .requestMatchers("/login", "/error", "/jacky917/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(loginSuccessHandler)
                        // 失敗計數、鎖定與稽核；所有失敗原因導向同一個網址，頁面顯示相同的訊息（詳細設計 §7.2）
                        .failureHandler(loginFailureHandler))
                // 同一個 IP 最近一分鐘失敗過多時，在檢查密碼之前就拒絕。不是 Bean：Spring Boot 會把 Filter Bean
                // 註冊到所有請求
                .addFilterBefore(new LoginAttemptGuard(loginAudits, events,
                        properties.getLoginProtection().getMaxFailuresPerIpPerMinute(), clock),
                        UsernamePasswordAuthenticationFilter.class)
                // POST /logout 也撤銷登入 Session
                .logout(logout -> logout.addLogoutHandler(logoutHandler).logoutSuccessUrl("/login?logout"))
                .sessionManagement(session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
                // 在其他裝置被登出（例如「登出所有裝置」）的瀏覽器回到登入頁
                .addFilterBefore(new LoginSessionValidationFilter(sessions, clock), AuthorizationFilter.class)
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

    /**
     * The official JDBC authorization service, linking each new
     * authorization to its login session (detailed design §5.2).
     * <p>
     * 官方 JDBC 授權服務，並把每一個新授權連結到其登入 Session（詳細設計 §5.2）。
     *
     * @param jdbcOperations      the JDBC operations of the authorization server database
     *                            <br>Authorization Server 資料庫的 JDBC operations
     * @param clients             the client repository
     *                            <br>client repository
     * @param links               the authorization links
     *                            <br>授權連結
     * @param transactionManager  saves an authorization and its link together
     *                            <br>在同一個交易中儲存授權與連結
     * @param clock               the clock for timestamps
     *                            <br>用於時間戳記的時鐘
     * @return the authorization service
     *         <br>授權服務
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository clients,
                                                    SessionAuthorizationRepository links,
                                                    PlatformTransactionManager transactionManager, Clock clock) {
        return new SessionLinkingAuthorizationService(new JdbcOAuth2AuthorizationService(jdbcOperations, clients), links,
                new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    SessionAuthorizationRepository sessionAuthorizationRepository(JdbcClient jdbcClient) {
        return new SessionAuthorizationRepository(jdbcClient);
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
    AuthSessionService authSessionService(JdbcClient jdbcClient, PlatformTransactionManager transactionManager,
                                          AuthorizationServerProperties properties, Clock clock) {
        return new AuthSessionService(jdbcClient, new TransactionTemplate(transactionManager),
                properties.getToken().getSessionMaxAge(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    RefreshTokenHistoryRepository refreshTokenHistoryRepository(JdbcClient jdbcClient) {
        return new RefreshTokenHistoryRepository(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    RefreshTokenReuseDetector refreshTokenReuseDetector(
            OAuth2AuthorizationService authorizations, JdbcClient jdbcClient, AuthorizationServerDialect dialect,
            SessionAuthorizationRepository links, AuthSessionService sessions, UserAccountService users,
            RefreshTokenHistoryRepository history, PlatformTransactionManager transactionManager,
            ApplicationEventPublisher events, AuthorizationServerProperties properties, Clock clock) {
        return new RefreshTokenReuseDetector(authorizations, jdbcClient, dialect, links, sessions, users, history,
                new TransactionTemplate(transactionManager), events, properties.getRefresh().getReuseGracePeriod(),
                properties.getRefresh().getHistoryRetention(), clock);
    }

    /**
     * Writes the security events to {@code login_audit}.
     * <p>
     * 把安全事件寫入 {@code login_audit}。
     *
     * @param jdbcClient  the JDBC client of the authorization server database
     *                    <br>Authorization Server 資料庫的 JDBC client
     * @return the listener
     *         <br>listener
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    JdbcLoginAuditListener jdbcLoginAuditListener(JdbcClient jdbcClient) {
        return new JdbcLoginAuditListener(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    AudienceResolver audienceResolver(AuthorizationServerProperties properties) {
        return new ConfiguredAudienceResolver(properties.getToken().getAudience());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AuthorityResolver authorityResolver(UserAccountService users, JdbcClient jdbcClient, Clock clock) {
        return new DefaultAuthorityResolver(users, jdbcClient, clock);
    }

    /**
     * Adds the jacky917 claims to access tokens and ID tokens.
     * <p>
     * 在 Access Token 與 ID Token 中加入 jacky917 的 claim。
     *
     * @return the token customizer
     *         <br>token customizer
     */
    @Bean
    @ConditionalOnMissingBean
    OAuth2TokenCustomizer<JwtEncodingContext> jacky917TokenCustomizer(
            AudienceResolver audienceResolver, AuthorityResolver authorityResolver,
            ClientProfileRepository clientProfiles, SessionAuthorizationRepository links, AuthSessionService sessions,
            UserAccountService users, ObjectProvider<TokenClaimsContributor> contributors, Clock clock) {
        return new Jacky917TokenCustomizer(audienceResolver, authorityResolver, clientProfiles, links, sessions, users,
                contributors.orderedStream().toList(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginSuccessHandler loginSuccessHandler(AuthSessionService sessions, UserAccountService users,
                                            ApplicationEventPublisher events, Clock clock) {
        return new LoginSuccessHandler(sessions, users, events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginFailureHandler loginFailureHandler(UserAccountService users, ApplicationEventPublisher events,
                                            AuthorizationServerProperties properties, Clock clock) {
        AuthorizationServerProperties.LoginProtection protection = properties.getLoginProtection();
        return new LoginFailureHandler(users, events, protection.getMaxFailures(), protection.getLockDuration(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    LoginAuditRepository loginAuditRepository(JdbcClient jdbcClient) {
        return new LoginAuditRepository(jdbcClient);
    }


    @Bean
    @ConditionalOnMissingBean
    Jacky917LogoutHandler jacky917LogoutHandler(AuthSessionService sessions, OAuth2AuthorizationService authorizations,
                                                SessionAuthorizationRepository links, ApplicationEventPublisher events,
                                                Clock clock) {
        return new Jacky917LogoutHandler(sessions, authorizations, links, events, clock);
    }

    /**
     * The account page, which shows times in the server's default time
     * zone.
     * <p>
     * 帳號頁，以伺服器的預設時區顯示時間。
     *
     * @param properties     the authorization server properties
     *                       <br>Authorization Server 設定屬性
     * @param sessions       the login sessions
     *                       <br>登入 Session
     * @param users          the user accounts
     *                       <br>使用者帳號
     * @param logoutHandler  ends login sessions
     *                       <br>結束登入 Session
     * @return the controller
     *         <br>controller
     */
    @Bean
    @ConditionalOnMissingBean
    AccountController jacky917AccountController(AuthorizationServerProperties properties, AuthSessionService sessions,
                                                UserAccountService users, Jacky917LogoutHandler logoutHandler) {
        return new AccountController(properties, sessions, users, logoutHandler, ZoneId.systemDefault());
    }

    @Bean
    @ConditionalOnMissingBean
    LoginController jacky917LoginController(AuthorizationServerProperties properties,
                                            ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
        return new LoginController(properties, clientRegistrations.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    PrincipalNormalizer principalNormalizer(UserAccountService users, Clock clock) {
        return new PrincipalNormalizer(users, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    FederatedIdentityService federatedIdentityService(JdbcClient jdbcClient, UserAccountService users,
                                                      PlatformTransactionManager transactionManager, Clock clock) {
        return new FederatedIdentityService(jdbcClient, users, new TransactionTemplate(transactionManager), clock);
    }

    /**
     * The fallback mapper for OpenID Connect providers such as Google.
     * Application mappers come first.
     * <p>
     * OpenID Connect 提供者（例如 Google）的預設 mapper；應用程式的 mapper 優先。
     *
     * @return the mapper
     *         <br>mapper
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    OidcFederatedUserInfoMapper oidcFederatedUserInfoMapper() {
        return new OidcFederatedUserInfoMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    FederatedLoginSuccessHandler federatedLoginSuccessHandler(
            ObjectProvider<FederatedUserInfoMapper> mappers, FederatedIdentityService identities, UserAccountService users,
            AuthSessionService sessions, PrincipalNormalizer normalizer,
            ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients, ApplicationEventPublisher events,
            Clock clock) {
        return new FederatedLoginSuccessHandler(mappers.orderedStream().toList(), identities, users, sessions, normalizer,
                authorizedClients.getIfAvailable(), events, clock);
    }
}
