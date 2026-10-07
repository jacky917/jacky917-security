package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold the given permission.
 * <p>
 * 要求呼叫端必須具備指定的權限（permission）。
 * <p>
 * Do not add a prefix yourself; {@code PERM_} is prepended automatically.
 * For example, {@code @RequirePerm("order:read")} checks for the authority
 * {@code PERM_order:read}.
 * <p>
 * 不需要自行加前綴，框架會自動加上 {@code PERM_}。例如
 * {@code @RequirePerm("order:read")} 等同於檢查 {@code PERM_order:read}。
 * <p>
 * The prefix is fixed to {@code PERM_} and does not follow
 * {@code jacky917.security.jwt.prefix.permission}. If you change that
 * property, use {@link RequireAny} with full authority names instead.
 * <p>
 * 前綴固定為 {@code PERM_}，不會跟隨
 * {@code jacky917.security.jwt.prefix.permission} 設定。若修改了該設定，
 * 請改用 {@code RequireAny} 並填寫完整 authority 名稱。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('PERM_{value}')")
public @interface RequirePerm {

    /**
     * The permission name, without the {@code PERM_} prefix.
     * <p>
     * 權限名稱，不含 {@code PERM_} 前綴。
     *
     * @return the permission name, for example {@code order:read}
     *         <br>權限名稱，例如 {@code order:read}
     */
    String value();
}

