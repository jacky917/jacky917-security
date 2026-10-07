package jacky917.demo.bff;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Security of the example BFF: login through the login service, API calls
 * with the user's access token, and logout from both.
 * <p>
 * 範例 BFF 的安全設定：透過登入服務登入、以使用者的 Access Token 呼叫 API，
 * 以及同時登出兩邊。
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(BffProperties.class)
class BffSecurityConfiguration {

    static final String REGISTRATION_ID = "jacky917";

    @Bean
    SecurityFilterChain bffSecurityFilterChain(HttpSecurity http, LogoutSuccessHandler logoutSuccessHandler)
            throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/index.html", "/bff.js", "/error").permitAll()
                        .anyRequest().authenticated())
                // 未登入時直接前往登入服務
                .oauth2Login(login -> login.loginPage("/oauth2/authorization/" + REGISTRATION_ID))
                // 頁面的指令碼以 X-XSRF-TOKEN 標頭送出 Cookie 中的 CSRF token
                .csrf(CsrfConfigurer::spa)
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler))
                // 頁面以 fetch 呼叫 API：未登入時回 401，由頁面決定是否前往登入，而不是收到登入頁的 HTML
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                PathPatternRequestMatcher.pathPattern("/api/**"))
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                PathPatternRequestMatcher.pathPattern("/me")));
        return http.build();
    }

    /**
     * After the BFF session ends, logs out of the login service too
     * (OpenID Connect RP-Initiated Logout), then returns to the home page.
     * <p>
     * 結束 BFF 的 Session 後，一併登出登入服務（OpenID Connect RP-Initiated
     * Logout），再回到首頁。
     * <p>
     * A request accepting JSON receives the target as {@code {"redirect":
     * "..."}} instead of a redirect.
     * <p>
     * 接受 JSON 的請求會收到 {@code {"redirect": "..."}}，而不是重導。
     */
    @Bean
    LogoutSuccessHandler logoutSuccessHandler(BffProperties properties) {
        return (request, response, authentication) -> {
            String home = ServletUriComponentsBuilder.fromContextPath(request).path("/").toUriString();
            String target = home;
            if (authentication != null && authentication.getPrincipal() instanceof OidcUser user) {
                target = UriComponentsBuilder.fromUriString(properties.authorizationServerUrl() + "/connect/logout")
                        .queryParam("id_token_hint", user.getIdToken().getTokenValue())
                        .queryParam("post_logout_redirect_uri", home)
                        .encode().toUriString();
            }
            // 頁面以 fetch 登出時看不到跨網域的重導目標，因此改回傳 JSON，由頁面自行前往
            if (MediaType.APPLICATION_JSON_VALUE.equals(request.getHeader(HttpHeaders.ACCEPT))) {
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"redirect\":\"" + target.replace("\"", "%22") + "\"}");
                return;
            }
            response.sendRedirect(target);
        };
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository registrations,
                                                          OAuth2AuthorizedClientRepository authorizedClients) {
        DefaultOAuth2AuthorizedClientManager manager =
                new DefaultOAuth2AuthorizedClientManager(registrations, authorizedClients);
        manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build());
        return new SerializedAuthorizedClientManager(manager);
    }

    /**
     * Calls the resource server with the signed-in user's access token,
     * refreshing it when it has expired.
     * <p>
     * 以已登入使用者的 Access Token 呼叫 Resource Server，過期時自動刷新。
     */
    @Bean
    RestClient resourceServerClient(OAuth2AuthorizedClientManager manager,
                                    OAuth2AuthorizedClientRepository authorizedClients, BffProperties properties) {
        OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
        interceptor.setClientRegistrationIdResolver(request -> REGISTRATION_ID);
        // Resource Server 回 401（例如 token 已被撤銷）時移除已儲存的 token，下次重新登入
        interceptor.setAuthorizationFailureHandler(
                OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClients));
        // Spring Boot 4 的 RestClient.Builder bean 來自另一個模組（spring-boot-starter-restclient），此處直接建立
        return RestClient.builder().baseUrl(properties.resourceServerUrl()).requestInterceptor(interceptor).build();
    }
}
