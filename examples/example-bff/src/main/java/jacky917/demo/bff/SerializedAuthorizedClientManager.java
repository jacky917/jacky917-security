package jacky917.demo.bff;

import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;


/**
 * Lets only one request per user obtain or refresh tokens at a time
 * (detailed design D19, BFF side).
 * <p>
 * 同一位使用者同時只有一個請求可以取得或刷新 token（詳細設計 D19 的 BFF 端）。
 * <p>
 * When several API calls find the access token expired together, each
 * would otherwise refresh with the same refresh token; the login service
 * rotates refresh tokens, so all but one would fail and log the user out.
 * Waiting requests reuse the token the first one obtained. A fixed set of
 * locks is shared by user name hash, so memory does not grow with the
 * number of users; two users sharing a lock only wait for each other's
 * short token request.
 * <p>
 * 多個 API 請求同時發現 Access Token 過期時，若各自以同一個 Refresh Token 刷新，
 * 由於登入服務會輪換 Refresh Token，只有一個會成功，其餘失敗並讓使用者被登出。
 * 等待中的請求會沿用第一個請求取得的 token。鎖的數量固定、依使用者名稱的雜湊
 * 分配，記憶體不會隨使用者人數增加；共用同一個鎖的兩位使用者只會等待對方短暫的
 * token 請求。
 */
class SerializedAuthorizedClientManager implements OAuth2AuthorizedClientManager {

    private static final int LOCK_COUNT = 64;

    private final OAuth2AuthorizedClientManager delegate;
    private final Object[] locks = new Object[LOCK_COUNT];

    SerializedAuthorizedClientManager(OAuth2AuthorizedClientManager delegate) {
        this.delegate = delegate;
        for (int i = 0; i < LOCK_COUNT; i++) {
            locks[i] = new Object();
        }
    }

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest request) {
        Object lock = locks[Math.floorMod(request.getPrincipal().getName().hashCode(), LOCK_COUNT)];
        synchronized (lock) {
            return delegate.authorize(request);
        }
    }
}
