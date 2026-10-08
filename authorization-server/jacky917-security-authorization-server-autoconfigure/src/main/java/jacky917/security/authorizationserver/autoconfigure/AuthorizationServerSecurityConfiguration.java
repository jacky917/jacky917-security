package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.account.AccountLinks;
import jacky917.security.authorizationserver.account.AccountMailer;
import jacky917.security.authorizationserver.account.ActionTokenService;
import jacky917.security.authorizationserver.account.PasswordChangeRequiredFilter;
import jacky917.security.authorizationserver.account.PasswordChangeService;
import jacky917.security.authorizationserver.account.RegistrationService;
import jacky917.security.authorizationserver.audit.JdbcLoginAuditListener;
import jacky917.security.authorizationserver.audit.LoginAuditRepository;
import jacky917.security.authorizationserver.authentication.AccountLockout;
import jacky917.security.authorizationserver.authentication.LoginAttemptGuard;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
import jacky917.security.authorizationserver.authentication.LoginFailureHandler;
import jacky917.security.authorizationserver.authentication.LoginSuccessHandler;
import jacky917.security.authorizationserver.authentication.PrincipalNormalizer;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.consent.AuditingAuthorizationConsentService;
import jacky917.security.authorizationserver.consent.AuthorizedApplicationService;
import jacky917.security.authorizationserver.consent.ScopeDescriptions;
import jacky917.security.authorizationserver.database.AuthorizationServerDialect;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginFailureHandler;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.FederatedUserInfoMapper;
import jacky917.security.authorizationserver.federation.GitHubFederatedUserInfoMapper;
import jacky917.security.authorizationserver.federation.LineIdTokens;
import jacky917.security.authorizationserver.federation.OidcFederatedUserInfoMapper;
import jacky917.security.authorizationserver.federation.PendingLinkService;
import jacky917.security.authorizationserver.keys.KeyEncryptor;
import jacky917.security.authorizationserver.mfa.MfaLoginFlow;
import jacky917.security.authorizationserver.mfa.MfaService;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.refresh.RefreshTokenHistoryRepository;
import jacky917.security.authorizationserver.refresh.RefreshTokenReuseDetector;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.Jacky917LogoutHandler;
import jacky917.security.authorizationserver.session.LoginSessionValidationFilter;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.session.SessionLinkingAuthorizationService;
import jacky917.security.authorizationserver.token.AudienceResolver;
import jacky917.security.authorizationserver.token.AuthorityResolver;
import jacky917.security.authorizationserver.token.ConfiguredAudienceResolver;
import jacky917.security.authorizationserver.token.DefaultAuthorityResolver;
import jacky917.security.authorizationserver.token.Jacky917TokenCustomizer;
import jacky917.security.authorizationserver.token.ScopeAudienceResolver;
import jacky917.security.authorizationserver.token.TokenClaimsContributor;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.AccountController;
import jacky917.security.authorizationserver.web.AccountLinkController;
import jacky917.security.authorizationserver.web.AccountMfaController;
import jacky917.security.authorizationserver.web.AccountPasswordController;
import jacky917.security.authorizationserver.web.ConsentController;
import jacky917.security.authorizationserver.web.IdentityProviders;
import jacky917.security.authorizationserver.web.LoginController;
import jacky917.security.authorizationserver.web.MfaChallengeController;
import jacky917.security.authorizationserver.web.MfaSetupSupport;
import jacky917.security.authorizationserver.web.PageSupport;
import jacky917.security.authorizationserver.web.PasswordResetController;
import jacky917.security.authorizationserver.web.RegistrationController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.crypto.password.PasswordEncoder;
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
                        // 第三方 client 的同意畫面（第 3、4 階段設計 §6.2）
                        .authorizationEndpoint(authorization -> authorization.consentPage(ConsentController.CONSENT_PATH))
                        // 刷新改經過重用偵測（詳細設計 §5.4）
                        .tokenEndpoint(token -> token.authenticationProviders(reuseDetector::install)))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // /userinfo 以 Access Token 存取
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 登入 Session 已失效時結束瀏覽器登入，授權請求因此回到登入頁，而不是錯誤頁
                .addFilterBefore(new LoginSessionValidationFilter(sessions, clock), AuthorizationFilter.class)
                // 必須變更密碼的登入不能繼續授權請求（D29）
                .addFilterBefore(new PasswordChangeRequiredFilter(), AuthorizationFilter.class);
        return http.build();
    }

    @Bean
    @Order(3)
    @ConditionalOnMissingBean(name = "loginSecurityFilterChain")
    SecurityFilterChain loginSecurityFilterChain(HttpSecurity http, LoginSuccessHandler loginSuccessHandler,
                                                 ObjectProvider<ClientRegistrationRepository> clientRegistrations,
                                                 ObjectProvider<FederatedLoginSuccessHandler> federatedLoginSuccessHandler,
                                                 ObjectProvider<FederatedLoginFailureHandler> federatedLoginFailureHandler,
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
                    // 記錄 OAuth 2.0 錯誤代碼並稽核；從帳號頁發起連結時回到帳號頁
                    .failureHandler(federatedLoginFailureHandler.getObject()));
        }
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(LoginController.SIGNED_IN_PATH, AccountController.ACCOUNT_PATH,
                                AccountController.ACCOUNT_PATH + "/**").authenticated()
                        .requestMatchers("/login", "/error", "/jacky917/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(loginSuccessHandler)
                        // 失敗計數、鎖定與稽核；所有密碼登入失敗導向同一個網址，頁面顯示相同的訊息（詳細設計 §7.2）
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
                .addFilterBefore(new PasswordChangeRequiredFilter(), AuthorizationFilter.class)
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentSecurityPolicy(csp -> csp.policyDirectives(PageSupport.CONTENT_SECURITY_POLICY)));
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
                                                                  RegisteredClientRepository clients,
                                                                  ApplicationEventPublisher events, Clock clock) {
        // 同意與撤回寫入稽核（第 3、4 階段設計 §6.2）
        return new AuditingAuthorizationConsentService(new JdbcOAuth2AuthorizationConsentService(jdbcOperations,
                clients), events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    ScopeDescriptions scopeDescriptions(JdbcClient jdbcClient) {
        return new ScopeDescriptions(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AuthorizedApplicationService authorizedApplicationService(JdbcClient jdbcClient, ScopeDescriptions scopes,
                                                              ApplicationEventPublisher events,
                                                              PlatformTransactionManager transactionManager,
                                                              Clock clock) {
        return new AuthorizedApplicationService(jdbcClient, scopes, events, new TransactionTemplate(transactionManager),
                clock);
    }

    @Bean
    @ConditionalOnMissingBean
    ConsentController jacky917ConsentController(AuthorizationServerProperties properties,
                                                RegisteredClientRepository clients, ClientProfileRepository profiles,
                                                OAuth2AuthorizationConsentService consents, ScopeDescriptions scopes) {
        return new ConsentController(properties, clients, profiles, consents, scopes);
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
     * @param events      publishes the write failures
     *                    <br>發布寫入失敗
     * @return the listener
     *         <br>listener
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    JdbcLoginAuditListener jdbcLoginAuditListener(JdbcClient jdbcClient, ApplicationEventPublisher events) {
        return new JdbcLoginAuditListener(jdbcClient, events);
    }

    @Bean
    @ConditionalOnMissingBean
    AudienceResolver audienceResolver(AuthorizationServerProperties properties, JdbcClient jdbcClient) {
        AuthorizationServerProperties.Token token = properties.getToken();
        return token.getAudienceStrategy() == AuthorizationServerProperties.AudienceStrategy.PER_SCOPE
                ? new ScopeAudienceResolver(jdbcClient, token.getAudience())
                : new ConfiguredAudienceResolver(token.getAudience());
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
            UserAccountService users, ObjectProvider<TokenClaimsContributor> contributors, ApplicationEventPublisher events,
            Clock clock) {
        return new Jacky917TokenCustomizer(audienceResolver, authorityResolver, clientProfiles, links, sessions, users,
                contributors.orderedStream().toList(), events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginSuccessHandler loginSuccessHandler(AuthSessionService sessions, UserAccountService users,
                                            ApplicationEventPublisher events, MfaLoginFlow mfaLoginFlow, Clock clock) {
        return new LoginSuccessHandler(sessions, users, events, mfaLoginFlow, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    MfaService mfaService(JdbcClient jdbcClient, UserAccountService users, KeyEncryptor keyEncryptor,
                          AuthorizationServerProperties properties, PlatformTransactionManager transactionManager,
                          Clock clock) {
        return new MfaService(jdbcClient, users, keyEncryptor, properties.getMfa().getRequiredRoles(),
                new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    MfaLoginFlow mfaLoginFlow(MfaService mfa, LoginCompletion completion, UserAccountService users, Clock clock) {
        return new MfaLoginFlow(mfa, completion, users, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    MfaSetupSupport jacky917MfaSetupSupport(AuthorizationServerProperties properties, UserAccountService users) {
        return new MfaSetupSupport(properties, users);
    }

    @Bean
    @ConditionalOnMissingBean
    MfaChallengeController jacky917MfaChallengeController(
            AuthorizationServerProperties properties, MfaLoginFlow flow, MfaService mfa, MfaSetupSupport setup,
            UserAccountService users, AccountLockout lockout,
            ObjectProvider<FederatedLoginSuccessHandler> federatedLogins, ApplicationEventPublisher events,
            Clock clock) {
        return new MfaChallengeController(properties, flow, mfa, setup, users, lockout, federatedLogins, events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    AccountMfaController jacky917AccountMfaController(AuthorizationServerProperties properties, MfaService mfa,
                                                      MfaSetupSupport setup, ApplicationEventPublisher events,
                                                      Clock clock) {
        return new AccountMfaController(properties, mfa, setup, events, clock, ZoneId.systemDefault());
    }

    @Bean
    @ConditionalOnMissingBean
    AccountLockout accountLockout(UserAccountService users, ApplicationEventPublisher events,
                                  AuthorizationServerProperties properties) {
        return new AccountLockout(users, events, properties.getLoginProtection().toLockoutPolicy());
    }

    @Bean
    @ConditionalOnMissingBean
    LoginFailureHandler loginFailureHandler(UserAccountService users, AccountLockout lockout,
                                            ApplicationEventPublisher events, Clock clock) {
        return new LoginFailureHandler(users, lockout, events, clock);
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
     * @param identities     the linked external accounts
     *                       <br>已連結的外部帳號
     * @param providers      the identity providers that can be linked
     *                       <br>可以連結的身分提供者
     * @param events         publishes the audit events
     *                       <br>發布稽核事件
     * @param clock          the clock
     *                       <br>時鐘
     * @return the controller
     *         <br>controller
     */
    @Bean
    @ConditionalOnMissingBean
    AccountController jacky917AccountController(AuthorizationServerProperties properties, AuthSessionService sessions,
                                                UserAccountService users, Jacky917LogoutHandler logoutHandler,
                                                FederatedIdentityService identities, IdentityProviders providers,
                                                AuthorizedApplicationService applications, MfaService mfa,
                                                ApplicationEventPublisher events, Clock clock) {
        return new AccountController(properties, sessions, users, logoutHandler, identities, providers, applications,
                mfa, events, clock, ZoneId.systemDefault());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    PasswordChangeService passwordChangeService(UserAccountService users, JdbcClient jdbcClient,
                                                PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                                                AccountLockout lockout, AuthSessionService sessions,
                                                AccountMailer mailer, AccountLinks links,
                                                ApplicationEventPublisher events,
                                                PlatformTransactionManager transactionManager, Clock clock) {
        return new PasswordChangeService(users, jdbcClient, passwordEncoder, passwordPolicy, lockout, sessions, mailer,
                links, events, new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    AccountPasswordController jacky917AccountPasswordController(AuthorizationServerProperties properties,
                                                                PasswordChangeService passwords,
                                                                PasswordPolicy passwordPolicy) {
        return new AccountPasswordController(properties, passwords, passwordPolicy);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginController jacky917LoginController(AuthorizationServerProperties properties, IdentityProviders providers,
                                            AccountMailer mailer) {
        return new LoginController(properties, providers, mailer);
    }

    @Bean
    @ConditionalOnMissingBean
    PasswordResetController jacky917PasswordResetController(AuthorizationServerProperties properties,
                                                            UserAccountService users, ActionTokenService tokens,
                                                            PasswordChangeService passwords,
                                                            PasswordPolicy passwordPolicy, AccountMailer mailer,
                                                            AccountLinks links) {
        return new PasswordResetController(properties, users, tokens, passwords, passwordPolicy, mailer, links);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX, name = "account.registration.enabled",
            havingValue = "true")
    RegistrationService registrationService(AuthorizationServerProperties properties, UserAccountService users,
                                            JdbcClient jdbcClient, PasswordEncoder passwordEncoder,
                                            ActionTokenService tokens, AccountMailer mailer, AccountLinks links,
                                            ApplicationEventPublisher events,
                                            PlatformTransactionManager transactionManager, Clock clock) {
        AuthorizationServerProperties.Account account = properties.getAccount();
        return new RegistrationService(users, jdbcClient, passwordEncoder, tokens, mailer, links, events,
                new TransactionTemplate(transactionManager), account.getEmailVerificationTtl(),
                account.getPasswordResetTtl(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX, name = "account.registration.enabled",
            havingValue = "true")
    RegistrationController jacky917RegistrationController(AuthorizationServerProperties properties,
                                                          RegistrationService registrations,
                                                          PasswordPolicy passwordPolicy) {
        return new RegistrationController(properties, registrations, passwordPolicy);
    }

    @Bean
    @ConditionalOnMissingBean
    IdentityProviders jacky917IdentityProviders(AuthorizationServerProperties properties,
                                                ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
        return new IdentityProviders(properties.getLogin().getProviders(), clientRegistrations.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    PendingLinkService pendingLinkService(JdbcClient jdbcClient, PlatformTransactionManager transactionManager,
                                          Clock clock) {
        return new PendingLinkService(jdbcClient, new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginCompletion loginCompletion(UserAccountService users, AuthSessionService sessions, PrincipalNormalizer normalizer,
                                    ApplicationEventPublisher events, Clock clock) {
        return new LoginCompletion(users, sessions, normalizer, events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    AccountLinkController jacky917AccountLinkController(
            AuthorizationServerProperties properties, PendingLinkService pendingLinks, UserAccountService users,
            FederatedIdentityService identities, PasswordEncoder passwordEncoder, LoginCompletion completion,
            MfaLoginFlow mfaLoginFlow, IdentityProviders providers, ApplicationEventPublisher events,
            AccountLockout lockout, Clock clock) {
        return new AccountLinkController(properties, pendingLinks, users, identities, passwordEncoder, completion,
                mfaLoginFlow, providers, events, lockout, clock);
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
                                                      PlatformTransactionManager transactionManager,
                                                      AuthorizationServerProperties properties, Clock clock) {
        return new FederatedIdentityService(jdbcClient, users, new TransactionTemplate(transactionManager),
                properties.getAccountLinking().getMode(), clock);
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

    /**
     * The mapper for GitHub, which is not an OpenID Connect provider. It
     * comes before the OpenID Connect fallback.
     * <p>
     * GitHub 的 mapper（GitHub 不是 OpenID Connect 提供者），排在 OpenID Connect
     * 預設 mapper 之前。
     *
     * @param clientRegistrations  the client registrations
     *                             <br>client registration
     * @return the mapper
     *         <br>mapper
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE - 10)
    GitHubFederatedUserInfoMapper gitHubFederatedUserInfoMapper(
            ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
        return new GitHubFederatedUserInfoMapper(clientRegistrations.getIfAvailable());
    }

    /**
     * Verifies the ID tokens of external logins: HS256 with the channel
     * secret for LINE, RS256 for the others.
     * <p>
     * 驗證第三方登入的 ID Token：LINE 以 channel secret 驗證 HS256，其餘為 RS256。
     *
     * @return the decoder factory
     *         <br>decoder factory
     */
    @Bean
    @ConditionalOnMissingBean
    JwtDecoderFactory<ClientRegistration> jacky917IdTokenDecoderFactory() {
        return LineIdTokens.decoderFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    FederatedLoginSuccessHandler federatedLoginSuccessHandler(
            ObjectProvider<FederatedUserInfoMapper> mappers, FederatedIdentityService identities,
            PendingLinkService pendingLinks, LoginCompletion completion, MfaLoginFlow mfaLoginFlow,
            ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients, ApplicationEventPublisher events,
            Clock clock) {
        return new FederatedLoginSuccessHandler(mappers.orderedStream().toList(), identities, pendingLinks, completion,
                mfaLoginFlow, authorizedClients.getIfAvailable(), events, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    FederatedLoginFailureHandler federatedLoginFailureHandler(ApplicationEventPublisher events, Clock clock) {
        return new FederatedLoginFailureHandler(events, clock);
    }
}
