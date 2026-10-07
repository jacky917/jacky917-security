package jacky917.security.resourceserver.autoconfigure.config;

import jacky917.security.resourceserver.autoconfigure.methodsecurity.Jacky917AuthorityEvaluator;
import jacky917.security.resourceserver.autoconfigure.properties.Jacky917SecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * Auto-configuration for the beans that the {@code @Require*} annotations
 * need: the {@code jacky917AuthorityEvaluator} bean and the settings for
 * {@code {value}} placeholders.
 * <p>
 * 註冊 {@code @Require*} 註解所需 bean 的自動配置：
 * {@code jacky917AuthorityEvaluator} 與 {@code {value}} 佔位符的設定。
 * <p>
 * Unlike {@link Jacky917SecurityAutoConfiguration}, it has no conditions:
 * it also applies when {@code jacky917.security.enabled=false} and in
 * non-servlet applications. An application that enables method security
 * itself can therefore keep using the annotations; without these beans
 * every annotated method would fail with an expression error (HTTP 500).
 * These beans only evaluate expressions and do not change any security
 * configuration.
 * <p>
 * 與 {@code Jacky917SecurityAutoConfiguration} 不同，本配置沒有任何條件：
 * {@code jacky917.security.enabled=false} 或非 Servlet 應用程式也會套用。
 * 因此自行啟用方法級授權的應用程式仍可使用這些註解；少了這些 bean，所有
 * 加上註解的方法都會因運算式錯誤而失敗（HTTP 500）。這些 bean 只負責判斷，
 * 不會改變任何安全設定。
 *
 * @author Jacky
 * @since 2.0.0
 */
@AutoConfiguration
@EnableConfigurationProperties(Jacky917SecurityProperties.class)
public class Jacky917AuthorityEvaluatorAutoConfiguration {

    /**
     * Creates the evaluator referenced by the {@code @Require*}
     * annotations as {@code @jacky917AuthorityEvaluator}.
     * <p>
     * 建立供 {@code @Require*} 註解以 {@code @jacky917AuthorityEvaluator}
     * 參照的判斷工具。
     *
     * @param properties  the starter properties that supply the prefixes
     *                    <br>提供前綴的 starter 設定屬性
     * @return an authority evaluator that uses the configured prefixes
     *         <br>使用設定前綴的 authority 判斷工具
     */
    @Bean("jacky917AuthorityEvaluator")
    @ConditionalOnMissingBean(name = "jacky917AuthorityEvaluator")
    public Jacky917AuthorityEvaluator jacky917AuthorityEvaluator(Jacky917SecurityProperties properties) {
        return new Jacky917AuthorityEvaluator(properties);
    }

    /**
     * Enables {@code {value}} placeholders in meta-annotations such as
     * {@code @RequireRole}.
     * <p>
     * 啟用 {@code @RequireRole} 等組合註解中的 {@code {value}} 佔位符。
     * <p>
     * Spring Security 7 already expands placeholders by default; the bean
     * declares the dependency explicitly and lets the application replace it.
     * <p>
     * Spring Security 7 預設已會展開佔位符；此 bean 明確宣告這項依賴，並讓應用程式
     * 可以替換。
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
}
