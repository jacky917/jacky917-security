package jacky917.security.autoconfigure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import jacky917.security.autoconfigure.authentication.JwtAuthoritiesExtractor;
import jacky917.security.autoconfigure.methodsecurity.Jacky917AuthorityEvaluator;
import jacky917.security.autoconfigure.properties.Jacky917SecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Jacky917 Security 自動配置核心。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Slf4j
@AutoConfiguration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableConfigurationProperties(Jacky917SecurityProperties.class)
@ConditionalOnProperty(name = "jacky917.security.enabled", havingValue = "true", matchIfMissing = true)
public class Jacky917SecurityAutoConfiguration {

    private final Jacky917SecurityProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt ->
                jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)
        ));

        // 4. 統一的 401/403 錯誤處理
        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(jsonAuthenticationEntryPoint())
                .accessDeniedHandler(jsonAccessDeniedHandler())
        );

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthoritiesExtractor jwtAuthoritiesExtractor() {
        return new JwtAuthoritiesExtractor(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter(JwtAuthoritiesExtractor jwtAuthoritiesExtractor) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwtAuthoritiesExtractor);
        return converter;
    }

    @Bean("jacky917AuthorityEvaluator")
    @ConditionalOnMissingBean(name = "jacky917AuthorityEvaluator")
    public Jacky917AuthorityEvaluator jacky917AuthorityEvaluator() {
        return new Jacky917AuthorityEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public AnnotationTemplateExpressionDefaults annotationTemplateExpressionDefaults() {
        return new AnnotationTemplateExpressionDefaults();
    }

    private org.springframework.security.web.AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return (request, response, authException) ->
                handleException(response, HttpStatus.UNAUTHORIZED, "未經驗證，無法存取資源", request.getRequestURI(), authException);
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

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }

    /**
     * 透過屬性控制方法級授權是否啟用。
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
