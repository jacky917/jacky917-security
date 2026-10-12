package jacky917.security.authorizationserver.admin;

import jacky917.security.core.Jacky917ClaimNames;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Who made an administration request: the user, the client, and the IP
 * address.
 * <p>
 * 發出管理請求的對象：使用者、client 與 IP。
 *
 * @param userId     the user, or {@code null} for a client acting for itself
 *                   ({@code client_credentials})
 *                   <br>使用者；client 以自身身分呼叫
 *                   （{@code client_credentials}）時為 {@code null}
 * @param clientId   the OAuth {@code client_id} that obtained the token, or
 *                   {@code null} if unknown
 *                   <br>取得 token 的 OAuth {@code client_id}；不明時為
 *                   {@code null}
 * @param ipAddress  the client IP address, or {@code null}
 *                   <br>用戶端 IP，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record AdminOperator(@Nullable String userId, @Nullable String clientId, @Nullable String ipAddress) {

    /**
     * Returns the operator of the current request, or an unknown operator
     * outside an administration request (for example in a test).
     * <p>
     * 回傳目前請求的操作者；不在管理請求中時（例如測試）回傳不明的操作者。
     *
     * @return the operator
     *         <br>操作者
     */
    public static AdminOperator current() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes
                servlet ? servlet.getRequest() : null;
        String ip = request == null ? null : request.getRemoteAddr();
        if (authentication instanceof JwtAuthenticationToken token) {
            boolean user = token.getToken().hasClaim(Jacky917ClaimNames.ASID);
            String client = token.getToken().getClaimAsString(Jacky917ClaimNames.CLIENT_ID);
            return new AdminOperator(user ? token.getToken().getSubject() : null,
                    client != null ? client : user ? null : token.getToken().getSubject(), ip);
        }
        return new AdminOperator(null, null, ip);
    }
}
