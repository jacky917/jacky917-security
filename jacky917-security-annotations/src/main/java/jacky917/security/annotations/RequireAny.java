package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * OR 條件：只要擁有其中任一 authority 即可通過。
 * <p>
 * 參數需使用完整 authority 名稱，並以 {@code |} 分隔。
 * 例如：{@code @RequireAny("ROLE_ADMIN|PERM_order:read")}。
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasAnyAuthority(authentication, '{value}')")
public @interface RequireAny {

    /**
     * 任一符合即可通過的 authority 清單（以 | 分隔）。
     */
    String value();
}

