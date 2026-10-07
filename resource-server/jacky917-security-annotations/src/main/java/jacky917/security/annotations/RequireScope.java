package jacky917.security.annotations;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold the given OAuth 2.0 scope.
 * <p>
 * 要求呼叫端必須具備指定的 OAuth 2.0 scope。
 * <p>
 * Do not add a prefix yourself; the configured scope prefix (by default
 * {@code SCOPE_}) is prepended automatically.
 * For example, {@code @RequireScope("profile.read")} checks for the
 * authority {@code SCOPE_profile.read}.
 * <p>
 * 不需要自行加前綴，框架會自動加上設定的前綴（預設
 * {@code SCOPE_}）。例如
 * {@code @RequireScope("profile.read")} 等同於檢查 {@code SCOPE_profile.read}。
 * <p>
 * The prefix comes from {@code jacky917.security.jwt.prefix.scope}
 * (default {@code SCOPE_}), so this annotation keeps working when the
 * prefix changes. A blank value always denies access. The value must not
 * contain a single quote ({@code '}).
 * <p>
 * 前綴取自 {@code jacky917.security.jwt.prefix.scope}（預設
 * {@code SCOPE_}），因此修改前綴後此註解仍可正常運作。值為空白時一律
 * 拒絕存取。值不可包含單引號（{@code '}）。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("@jacky917AuthorityEvaluator.hasScope(authentication, '{value}')")
public @interface RequireScope {

    /**
     * The scope name, without the {@code SCOPE_} prefix.
     * <p>
     * Scope 名稱，不含 {@code SCOPE_} 前綴。
     *
     * @return the scope name, for example {@code profile.read}
     *         <br>Scope 名稱，例如 {@code profile.read}
     */
    String value();
}

