package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold at least one listed authority (logical OR).
 * <p>
 * 要求呼叫端至少具備其中一個列出的 authority（OR 條件）。
 * <p>
 * The value lists full authority names, including their prefixes, separated
 * by {@code |}. For example, {@code @RequireAny("ROLE_ADMIN|PERM_order:read")}
 * passes when the caller has either {@code ROLE_ADMIN} or
 * {@code PERM_order:read}. Blank entries are ignored; if no entry remains,
 * access is denied.
 * <p>
 * 參數需使用含前綴的完整 authority 名稱，並以 {@code |} 分隔。例如
 * {@code @RequireAny("ROLE_ADMIN|PERM_order:read")} 只要呼叫端具備
 * {@code ROLE_ADMIN} 或 {@code PERM_order:read} 其中之一即可通過。空白項目
 * 會被忽略；若沒有剩下任何項目，則拒絕存取。
 * <p>
 * The value is inserted into a SpEL string literal, so it must not contain
 * a single quote ({@code '}).
 * <p>
 * 參數值會被插入 SpEL 字串常值中，因此不可包含單引號（{@code '}）。
 *
 * @see RequireAll
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasAnyAuthority(authentication, '{value}')")
public @interface RequireAny {

    /**
     * The candidate authorities, separated by {@code |}.
     * <p>
     * 任一符合即可通過的 authority 清單，以 {@code |} 分隔。
     *
     * @return the full authority names joined by {@code |}
     *         <br>以 {@code |} 串接的完整 authority 名稱
     */
    String value();
}

