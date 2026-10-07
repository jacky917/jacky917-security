package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold every listed authority (logical AND).
 * <p>
 * 要求呼叫端同時具備所有列出的 authority（AND 條件）。
 * <p>
 * The value lists full authority names, including their prefixes, separated
 * by {@code |}. For example, {@code @RequireAll("ROLE_ADMIN|PERM_order:write")}
 * passes only when the caller has both {@code ROLE_ADMIN} and
 * {@code PERM_order:write}. Blank entries are ignored; if no entry remains,
 * access is denied.
 * <p>
 * 參數需使用含前綴的完整 authority 名稱，並以 {@code |} 分隔。例如
 * {@code @RequireAll("ROLE_ADMIN|PERM_order:write")} 只有在呼叫端同時具備
 * {@code ROLE_ADMIN} 與 {@code PERM_order:write} 時才會通過。空白項目會被
 * 忽略；若沒有剩下任何項目，則拒絕存取。
 * <p>
 * The value is inserted into a SpEL string literal, so it must not contain
 * a single quote ({@code '}).
 * <p>
 * 參數值會被插入 SpEL 字串常值中，因此不可包含單引號（{@code '}）。
 *
 * @see RequireAny
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasAllAuthorities(authentication, '{value}')")
public @interface RequireAll {

    /**
     * The required authorities, separated by {@code |}.
     * <p>
     * 必須全部具備的 authority 清單，以 {@code |} 分隔。
     *
     * @return the full authority names joined by {@code |}
     *         <br>以 {@code |} 串接的完整 authority 名稱
     */
    String value();
}

