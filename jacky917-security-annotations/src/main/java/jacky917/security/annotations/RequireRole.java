package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求呼叫端必須具備指定角色。
 * <p>
 * 角色值不需要自行加前綴，框架會自動套用 {@code ROLE_}。
 * 例如：{@code @RequireRole("ADMIN")} 等同於檢查 {@code ROLE_ADMIN}。
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('ROLE_{value}')")
public @interface RequireRole {

    /**
     * 角色名稱（不含 ROLE_ 前綴）。
     */
    String value();
}

