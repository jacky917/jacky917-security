package jacky917.security.resourceserver.autoconfigure.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the jacky917-security resource server
 * starter, bound from {@code jacky917.security.*}.
 * <p>
 * jacky917-security Resource Server starter 的設定屬性，綁定自
 * {@code jacky917.security.*}。
 *
 * @author Jacky
 * @since 0.0.1
 */
@Getter
@Setter
@ConfigurationProperties(prefix = Jacky917SecurityProperties.PREFIX)
public class Jacky917SecurityProperties {

    /**
     * The property prefix, {@code jacky917.security}.
     * <p>
     * 設定屬性的前綴 {@code jacky917.security}。
     */
    public static final String PREFIX = "jacky917.security";

    /**
     * Whether the starter's auto-configuration is enabled.
     * <p>
     * 是否啟用本 starter 的自動配置。
     */
    private boolean enabled = true;

    /**
     * Request patterns that are accessible without authentication. Setting
     * this property replaces the default instead of adding to it. The
     * default only permits the actuator health endpoint; add Swagger and
     * OpenAPI paths explicitly when they should be public.
     * <p>
     * 不需驗證即可存取的請求路徑。設定此屬性會取代預設值，而不是附加在後面。
     * 預設只放行 actuator health；需要公開 Swagger／OpenAPI 時請自行加入。
     */
    private List<String> permitAllPatterns = new ArrayList<>(List.of("/actuator/health"));

    /**
     * JWT claim and authority prefix settings.
     * <p>
     * JWT claim 與權限前綴設定。
     */
    private Jwt jwt = new Jwt();

    /**
     * JWT settings, bound from {@code jacky917.security.jwt.*}.
     * <p>
     * JWT 設定，綁定自 {@code jacky917.security.jwt.*}。
     */
    @Getter
    @Setter
    public static class Jwt {
        /**
         * Names of the claims that carry authorities.
         * <p>
         * 攜帶權限資訊的 claim 名稱。
         */
        private Claims claims = new Claims();

        /**
         * Prefixes added to authorities extracted from each claim.
         * <p>
         * 從各 claim 提取出的 authority 所加上的前綴。
         */
        private Prefix prefix = new Prefix();

        /**
         * Names of the JWT claims that carry authorities. A blank name
         * disables extraction from that claim.
         * <p>
         * 攜帶權限資訊的 JWT claim 名稱。名稱為空白時，不從該 claim 提取。
         */
        @Getter
        @Setter
        public static class Claims {
            /**
             * Name of the claim that holds roles.
             * <p>
             * 存放角色的 claim 名稱。
             */
            private String roles = "roles";
            /**
             * Name of the claim that holds permissions.
             * <p>
             * 存放權限的 claim 名稱。
             */
            private String permissions = "permissions";
            /**
             * Name of the claim that holds scopes as a space-separated
             * string.
             * <p>
             * 以空白分隔字串存放 scope 的 claim 名稱。
             */
            private String scope = "scope";
            /**
             * Name of the claim that holds scopes as an array.
             * <p>
             * 以陣列存放 scope 的 claim 名稱。
             */
            private String scp = "scp";
        }

        /**
         * Prefixes added to extracted authorities. The {@code @RequireRole},
         * {@code @RequirePerm}, and {@code @RequireScope} annotations use the
         * same prefixes, so they keep working when these values change.
         * <p>
         * 加在提取出的 authority 前面的前綴。{@code @RequireRole}、
         * {@code @RequirePerm} 與 {@code @RequireScope} 註解使用相同的前綴，
         * 因此修改這些值後註解仍可正常運作。
         */
        @Getter
        @Setter
        public static class Prefix {
            /**
             * Prefix for role authorities.
             * <p>
             * 角色 authority 的前綴。
             */
            private String role = "ROLE_";
            /**
             * Prefix for permission authorities.
             * <p>
             * 權限 authority 的前綴。
             */
            private String permission = "PERM_";
            /**
             * Prefix for scope authorities.
             * <p>
             * Scope authority 的前綴。
             */
            private String scope = "SCOPE_";
        }
    }
}
