package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求呼叫端必須具備指定權限。
 * <p>
 * 權限值不需要自行加前綴，框架會自動套用 {@code PERM_}。
 * 例如：{@code @RequirePerm("order:read")} 等同於檢查 {@code PERM_order:read}。
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('PERM_{value}')")
public @interface RequirePerm {

    /**
     * 權限名稱（不含 PERM_ 前綴）。
     */
    String value();
}

