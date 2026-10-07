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
 * Do not add a prefix yourself; the configured permission prefix (by default
 * {@code PERM_}) is prepended automatically.
 * For example, {@code @RequirePerm("order:read")} checks for the authority
 * {@code PERM_order:read}.
 * <p>
 * 不需要自行加前綴，框架會自動加上設定的前綴（預設
 * {@code PERM_}）。例如
 * {@code @RequirePerm("order:read")} 等同於檢查 {@code PERM_order:read}。
 * <p>
 * The prefix comes from {@code jacky917.security.jwt.prefix.permission}
 * (default {@code PERM_}), so this annotation keeps working when the
 * prefix changes. A blank value always denies access. The value must not
 * contain a single quote ({@code '}).
 * <p>
 * 前綴取自 {@code jacky917.security.jwt.prefix.permission}（預設
 * {@code PERM_}），因此修改前綴後此註解仍可正常運作。值為空白時一律
 * 拒絕存取。值不可包含單引號（{@code '}）。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasPerm(authentication, '{value}')")
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

