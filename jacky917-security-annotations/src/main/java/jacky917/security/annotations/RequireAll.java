package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * AND 條件：必須同時擁有全部 authority 才能通過。
 * <p>
 * 參數需使用完整 authority 名稱，並以 {@code |} 分隔。
 * 例如：{@code @RequireAll("ROLE_ADMIN|PERM_order:write")}。
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasAllAuthorities(authentication, '{value}')")
public @interface RequireAll {

    /**
     * 必須全部符合的 authority 清單（以 | 分隔）。
     */
    String value();
}

