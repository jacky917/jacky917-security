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
 * Do not add a prefix yourself; the configured role prefix (by default
 * {@code ROLE_}) is prepended automatically.
 * For example, {@code @RequireRole("ADMIN")} checks for the authority
 * {@code ROLE_ADMIN}.
 * <p>
 * 不需要自行加前綴，框架會自動加上設定的前綴（預設
 * {@code ROLE_}）。例如
 * {@code @RequireRole("ADMIN")} 等同於檢查 {@code ROLE_ADMIN}。
 * <p>
 * The prefix comes from {@code jacky917.security.jwt.prefix.role}
 * (default {@code ROLE_}), so this annotation keeps working when the
 * prefix changes. A blank value always denies access. The value must not
 * contain a single quote ({@code '}).
 * <p>
 * 前綴取自 {@code jacky917.security.jwt.prefix.role}（預設
 * {@code ROLE_}），因此修改前綴後此註解仍可正常運作。值為空白時一律
 * 拒絕存取。值不可包含單引號（{@code '}）。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasRole(authentication, '{value}')")
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

