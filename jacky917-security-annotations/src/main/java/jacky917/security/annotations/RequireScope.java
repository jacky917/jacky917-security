package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 要求呼叫端必須具備指定 scope。
 * <p>
 * scope 值不需要自行加前綴，框架會自動套用 {@code SCOPE_}。
 * 例如：{@code @RequireScope("profile.read")} 等同於檢查 {@code SCOPE_profile.read}。
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('SCOPE_{value}')")
public @interface RequireScope {

    /**
     * Scope 名稱（不含 SCOPE_ 前綴）。
     */
    String value();
}

