package jacky917.security.autoconfigure.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * jacky917-security-starter 的核心配置屬性。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Getter
@Setter
@ConfigurationProperties(prefix = Jacky917SecurityProperties.PREFIX)
public class Jacky917SecurityProperties {

    public static final String PREFIX = "jacky917.security";

    /**
     * 是否啟用 jacky917-security-starter。
     */
    private boolean enabled = true;

    /**
     * 公共端點，允許未經身份驗證的訪問。
     * 預設包含 actuator health 與 swagger/openapi 常用路徑。
     */
    private List<String> permitAllPatterns = new ArrayList<>(List.of(
            "/actuator/health",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/swagger-ui/index.html"
    ));

    /**
     * 方法級安全配置。
     */
    private MethodSecurity methodSecurity = new MethodSecurity();

    /**
     * JWT Claims 相關配置。
     */
    private Jwt jwt = new Jwt();

    /**
     * 是否啟用詳細的偵錯日誌。
     */
    private boolean debugLog = false;

    @Getter
    @Setter
    public static class MethodSecurity {
        /**
         * 是否啟用方法級安全 (@PreAuthorize, @PostAuthorize, etc.)。
         */
        private boolean enabled = true;
    }

    @Getter
    @Setter
    public static class Jwt {
        /**
         * Claims 映射相關配置。
         */
        private Claims claims = new Claims();

        /**
         * 權限前綴相關配置。
         */
        private Prefix prefix = new Prefix();

        @Getter
        @Setter
        public static class Claims {
            /**
             * 用於提取角色的 Claim 名稱。
             */
            private String roles = "roles";
            /**
             * 用於提取權限的 Claim 名稱。
             */
            private String permissions = "permissions";
            /**
             * 用於提取範疇 (scope) 的 Claim 名稱 (字串形式)。
             */
            private String scope = "scope";
            /**
             * 用於提取範疇 (scope) 的 Claim 名稱 (陣列形式)。
             */
            private String scp = "scp";
        }

        @Getter
        @Setter
        public static class Prefix {
            /**
             * 角色的權限前綴。
             */
            private String role = "ROLE_";
            /**
             * 權限的權限前綴。
             */
            private String permission = "PERM_";
            /**
             * 範疇 (scope) 的權限前綴。
             */
            private String scope = "SCOPE_";
        }
    }
}
