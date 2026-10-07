package jacky917.security.resourceserver.autoconfigure.config;

import jakarta.servlet.http.HttpServletResponse;
import jacky917.security.resourceserver.autoconfigure.authentication.JwtAuthoritiesExtractor;
import jacky917.security.resourceserver.autoconfigure.methodsecurity.Jacky917AuthorityEvaluator;
import jacky917.security.resourceserver.autoconfigure.properties.Jacky917SecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Auto-configuration that turns a servlet application into a stateless JWT
 * resource server.
 * <p>
 * 將 Servlet 應用程式設定為無狀態 JWT 資源伺服器的自動配置。
 * <p>
 * It registers a {@link SecurityFilterChain} that permits the configured
 * public patterns, requires authentication for every other request, maps
 * JWT claims to authorities, and writes JSON bodies for 401 and 403
 * responses. A 401 response also carries the RFC 6750
 * {@code WWW-Authenticate} header. It also enables method security and the beans used by the
 * {@code @Require*} annotations. Every bean backs off when the application
 * defines its own bean of the same type (or name, for the evaluator).
 * <p>
 * 會註冊一個 {@code SecurityFilterChain}：放行設定的公開路徑、其他請求一律
 * 需要驗證、將 JWT claims 轉換為 authority，並在 401 與 403 時回傳 JSON；
 * 401 回應另外帶有 RFC 6750 的 {@code WWW-Authenticate} 標頭。
 * 同時啟用方法級授權，以及 {@code @Require*} 註解所需的 bean。應用程式若自行
 * 定義相同型別（判斷工具則為相同名稱）的 bean，對應的預設 bean 便不會建立。
 * <p>
 * The whole configuration is disabled when
 * {@code jacky917.security.enabled=false}. It runs before Spring Boot's own
 * security auto-configurations so that its filter chain and JWT converter
 * take precedence over Boot's defaults.
 * <p>
 * 設定 {@code jacky917.security.enabled=false} 時整個配置停用。此配置會在
 * Spring Boot 內建的安全性自動配置之前執行，確保其 filter chain 與 JWT
 * 轉換器優先於 Boot 的預設值。
 * <p>
 * Error bodies are serialized with the application's Jackson
 * {@code JsonMapper} bean when exactly one exists, so {@code spring.jackson.*}
 * settings apply; otherwise a default mapper is used.
 * <p>
 * 錯誤回應以應用程式唯一的 Jackson {@code JsonMapper} bean 序列化，因此
 * {@code spring.jackson.*} 設定會生效；若沒有或不只一個，則使用預設的 mapper。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Slf4j
// 以字串指定，類別不存在時會被忽略而不是啟動失敗；名稱是否正確由 AutoConfigurationOrderingIntegrationTest 檢查
@AutoConfiguration(beforeName = {
        "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration"
})
@RequiredArgsConstructor
@EnableWebSecurity
@EnableConfigurationProperties(Jacky917SecurityProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "jacky917.security.enabled", havingValue = "true", matchIfMissing = true)
public class Jacky917SecurityAutoConfiguration {

    private static final JsonMapper DEFAULT_JSON_MAPPER = JsonMapper.builder().build();

    private final Jacky917SecurityProperties properties;
    private final ObjectProvider<JsonMapper> jsonMapperProvider;

    /**
     * Creates the default stateless JWT security filter chain.
     * <p>
     * 建立預設的無狀態 JWT security filter chain。
     * <p>
     * Sessions are never created and CSRF protection is disabled, because
     * every request carries a bearer token. Requests matching
     * {@code jacky917.security.permit-all-patterns} are permitted; all
     * others must be authenticated.
     * <p>
     * 由於每個請求都攜帶 bearer token，因此不建立 session 並停用 CSRF 防護。
     * 符合 {@code jacky917.security.permit-all-patterns} 的請求會被放行，
     * 其餘請求皆須通過驗證。
     *
     * @param http                        the builder to configure
     *                                    <br>要設定的 {@code HttpSecurity} 建構器
     * @param jwtAuthenticationConverter  the converter that turns a JWT into
     *                                    an authentication token
     *                                    <br>將 JWT 轉換為驗證 token 的轉換器
     * @return the built security filter chain
     *         <br>建置完成的 security filter chain
     * @throws Exception if the filter chain cannot be built
     *         <br>若無法建置 filter chain
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain jacky917SecurityFilterChain(
            HttpSecurity http,
            JwtAuthenticationConverter jwtAuthenticationConverter
    ) throws Exception {
        if (properties.isDebugLog()) {
            log.info("Initializing Jacky917SecurityFilterChain...");
        }

        // 1. 基本配置：無狀態、禁用 CSRF
        http
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable());

        // 2. 路由權限
        http.authorizeHttpRequests(auth -> {
            if (!properties.getPermitAllPatterns().isEmpty()) {
                auth.requestMatchers(properties.getPermitAllPatterns().toArray(new String[0])).permitAll();
            }
            auth.anyRequest().authenticated();
        });

        // 3. 資源伺服器配置：強制使用 JWT 並自訂權限轉換
        //    Token 無效／過期時由 BearerTokenAuthenticationFilter 處理，需另外指定 entry point 才會回傳 JSON
        http.oauth2ResourceServer(oauth2 -> oauth2
                .authenticationEntryPoint(jsonAuthenticationEntryPoint())
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
        );

        // 4. 統一的 401/403 錯誤處理
        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(jsonAuthenticationEntryPoint())
                .accessDeniedHandler(jsonAccessDeniedHandler())
        );

        return http.build();
    }

    /**
     * Creates the extractor that maps JWT claims to authorities.
     * <p>
     * 建立將 JWT claims 轉換為 authority 的提取器。
     *
     * @return a new extractor bound to the starter properties
     *         <br>綁定 starter 設定屬性的新提取器
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthoritiesExtractor jwtAuthoritiesExtractor() {
        return new JwtAuthoritiesExtractor(properties);
    }

    /**
     * Creates the JWT authentication converter that uses the given
     * authorities extractor.
     * <p>
     * 建立使用指定 authority 提取器的 JWT 驗證轉換器。
     *
     * @param jwtAuthoritiesExtractor  the extractor that supplies granted
     *                                 authorities
     *                                 <br>提供 granted authority 的提取器
     * @return a converter whose principal name is the {@code sub} claim
     *         <br>以 {@code sub} claim 作為 principal 名稱的轉換器
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter(JwtAuthoritiesExtractor jwtAuthoritiesExtractor) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwtAuthoritiesExtractor);
        return converter;
    }

    /**
     * Creates the evaluator referenced by {@code @RequireAny} and
     * {@code @RequireAll} as {@code @jacky917AuthorityEvaluator}.
     * <p>
     * 建立供 {@code @RequireAny} 與 {@code @RequireAll} 以
     * {@code @jacky917AuthorityEvaluator} 參照的判斷工具。
     *
     * @return a new authority evaluator
     *         <br>新的 authority 判斷工具
     */
    @Bean("jacky917AuthorityEvaluator")
    @ConditionalOnMissingBean(name = "jacky917AuthorityEvaluator")
    public Jacky917AuthorityEvaluator jacky917AuthorityEvaluator() {
        return new Jacky917AuthorityEvaluator();
    }

    /**
     * Enables {@code {value}} placeholders in meta-annotations such as
     * {@code @RequireRole}.
     * <p>
     * 啟用 {@code @RequireRole} 等組合註解中的 {@code {value}} 佔位符。
     * <p>
     * The method is static so that the bean is available before Spring
     * Security creates its method security interceptors.
     * <p>
     * 此方法宣告為 static，確保 bean 在 Spring Security 建立方法級授權攔截器
     * 之前即可使用。
     *
     * @return the default template expression settings
     *         <br>預設的樣板運算式設定
     */
    @Bean
    @ConditionalOnMissingBean
    public static AnnotationTemplateExpressionDefaults annotationTemplateExpressionDefaults() {
        return new AnnotationTemplateExpressionDefaults();
    }

    private org.springframework.security.web.AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        // 先由 BearerTokenAuthenticationEntryPoint 設定 RFC 6750 的 WWW-Authenticate 標頭，再寫入 JSON 內容
        BearerTokenAuthenticationEntryPoint bearerEntryPoint = new BearerTokenAuthenticationEntryPoint();
        return (request, response, authException) -> {
            bearerEntryPoint.commence(request, response, authException);
            handleException(response, HttpStatus.UNAUTHORIZED, "未經驗證，無法存取資源", request.getRequestURI(), authException);
        };
    }


    private org.springframework.security.web.access.AccessDeniedHandler jsonAccessDeniedHandler() {
        return (request, response, accessDeniedException) ->
                handleException(response, HttpStatus.FORBIDDEN, "權限不足，禁止存取", request.getRequestURI(), accessDeniedException);
    }

    private void handleException(HttpServletResponse response, HttpStatus status, String message, String path, Exception ex) throws IOException {
        if (properties.isDebugLog()) {
            log.warn("Security exception caught: status={}, message={}, path={}, exception={}", status, message, path, ex.getClass().getSimpleName());
        }
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("errorCode", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", path);

        JsonMapper jsonMapper = jsonMapperProvider.getIfUnique(() -> DEFAULT_JSON_MAPPER);
        response.getWriter().write(jsonMapper.writeValueAsString(body));
    }

    /**
     * Enables method security unless
     * {@code jacky917.security.method-security.enabled=false}.
     * <p>
     * 啟用方法級授權，除非設定
     * {@code jacky917.security.method-security.enabled=false}。
     */
    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
    @ConditionalOnProperty(
            name = "jacky917.security.method-security.enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    static class MethodSecurityConfiguration {
    }
}
