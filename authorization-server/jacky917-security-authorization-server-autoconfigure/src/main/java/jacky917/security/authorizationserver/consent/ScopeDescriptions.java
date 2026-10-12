package jacky917.security.authorizationserver.consent;

import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Describes scopes to users with the names and descriptions in
 * {@code app_scope}.
 * <p>
 * 以 {@code app_scope} 中的名稱與說明向使用者描述 scope。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ScopeDescriptions {

    private final JdbcClient jdbc;

    /**
     * Creates the descriptions.
     * <p>
     * 建立 scope 描述。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public ScopeDescriptions(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Describes scopes, in the given order. A scope missing from
     * {@code app_scope} is shown by its code and needs consent.
     * <p>
     * 依指定的順序描述 scope。{@code app_scope} 中沒有的 scope 以代碼顯示，並
     * 需要同意。
     *
     * @param codes  the scope codes
     *               <br>scope 代碼
     * @return the descriptions
     *         <br>scope 描述
     */
    public List<Scope> describe(Collection<String> codes) {
        if (codes.isEmpty()) {
            return List.of();
        }
        Map<String, Scope> known = jdbc.sql("SELECT code, display_name, description, consent_required FROM app_scope "
                        + "WHERE code IN (:codes)")
                .param("codes", List.copyOf(codes))
                .query((rs, rowNum) -> new Scope(rs.getString(1), rs.getString(2), rs.getString(3), rs.getBoolean(4)))
                .list().stream().collect(Collectors.toMap(Scope::code, Function.identity()));
        return codes.stream().map(code -> known.getOrDefault(code, new Scope(code, code, null, true))).toList();
    }

    /**
     * A scope as users see it.
     * <p>
     * 使用者看到的 scope。
     *
     * @param code             the scope code
     *                         <br>scope 代碼
     * @param name             the name shown to users
     *                         <br>顯示給使用者的名稱
     * @param description      what it allows, or {@code null}
     *                         <br>它允許做什麼，或 {@code null}
     * @param consentRequired  whether users are asked to consent to it
     *                         <br>是否要求使用者同意
     */
    public record Scope(String code, String name, @Nullable String description, boolean consentRequired) {
    }
}
