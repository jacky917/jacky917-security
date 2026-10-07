package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold the given role.
 * <p>
 * 要求呼叫端必須具備指定角色。
 * <p>
 * Do not add a prefix yourself; {@code ROLE_} is prepended automatically.
 * For example, {@code @RequireRole("ADMIN")} checks for the authority
 * {@code ROLE_ADMIN}.
 * <p>
 * 不需要自行加前綴，框架會自動加上 {@code ROLE_}。例如
 * {@code @RequireRole("ADMIN")} 等同於檢查 {@code ROLE_ADMIN}。
 * <p>
 * The prefix is fixed to {@code ROLE_} and does not follow
 * {@code jacky917.security.jwt.prefix.role}. If you change that property,
 * use {@link RequireAny} with full authority names instead.
 * <p>
 * 前綴固定為 {@code ROLE_}，不會跟隨 {@code jacky917.security.jwt.prefix.role}
 * 設定。若修改了該設定，請改用 {@code RequireAny} 並填寫完整 authority 名稱。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('ROLE_{value}')")
public @interface RequireRole {

    /**
     * The role name, without the {@code ROLE_} prefix.
     * <p>
     * 角色名稱，不含 {@code ROLE_} 前綴。
     *
     * @return the role name, for example {@code ADMIN}
     *         <br>角色名稱，例如 {@code ADMIN}
     */
    String value();
}

