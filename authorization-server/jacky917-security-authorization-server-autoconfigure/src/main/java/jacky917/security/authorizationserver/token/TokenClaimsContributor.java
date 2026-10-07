package jacky917.security.authorizationserver.token;

import jacky917.security.authorizationserver.user.UserAccount;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.Optional;

/**
 * Adds application-specific claims to tokens. Every bean of this type is
 * called after the starter's own claims are set.
 * <p>
 * 在 token 中加入應用程式自己的 claim。所有此型別的 bean 都會在 starter 的
 * claim 設定完成後被呼叫。
 * <p>
 * Do not remove or overwrite {@code sid}, {@code nonce}, or {@code azp}:
 * Spring Security uses them to validate logout and the authentication
 * response. Claim values are stored with the authorization and read back
 * on refresh, so use strings, numbers, booleans, lists, and maps only;
 * collections are converted to {@code ArrayList} and
 * {@code LinkedHashMap} after the contributors run.
 * <p>
 * 不可移除或覆寫 {@code sid}、{@code nonce}、{@code azp}：Spring Security 以它們
 * 驗證登出與驗證回應。Claim 的值會隨授權儲存、刷新時再讀回，因此只能使用字串、
 * 數字、布林、List 與 Map；所有 contributor 執行後，集合會轉換為
 * {@code ArrayList} 與 {@code LinkedHashMap}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@FunctionalInterface
public interface TokenClaimsContributor {

    /**
     * Adds claims to the token being issued.
     * <p>
     * 在正在簽發的 token 中加入 claim。
     *
     * @param context  the encoding context, with the token type and claims
     *                 <br>編碼內容，含 token 類型與 claim
     * @param user     the user, or empty for {@code client_credentials}
     *                 <br>使用者；{@code client_credentials} 時為空
     */
    void contribute(JwtEncodingContext context, Optional<UserAccount> user);
}
