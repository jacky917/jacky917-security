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
 * Do not add a prefix yourself; {@code SCOPE_} is prepended automatically.
 * For example, {@code @RequireScope("profile.read")} checks for the
 * authority {@code SCOPE_profile.read}.
 * <p>
 * 不需要自行加前綴，框架會自動加上 {@code SCOPE_}。例如
 * {@code @RequireScope("profile.read")} 等同於檢查 {@code SCOPE_profile.read}。
 * <p>
 * The prefix is fixed to {@code SCOPE_} and does not follow
 * {@code jacky917.security.jwt.prefix.scope}. If you change that property,
 * use {@link RequireAny} with full authority names instead.
 * <p>
 * 前綴固定為 {@code SCOPE_}，不會跟隨 {@code jacky917.security.jwt.prefix.scope}
 * 設定。若修改了該設定，請改用 {@code RequireAny} 並填寫完整 authority 名稱。
 *
 * @since 0.0.1
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@PreAuthorize("hasAuthority('SCOPE_{value}')")
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

