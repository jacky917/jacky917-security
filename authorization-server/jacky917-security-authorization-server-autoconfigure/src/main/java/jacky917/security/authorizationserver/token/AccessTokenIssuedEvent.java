package jacky917.security.authorizationserver.token;

import java.util.Objects;

/**
 * Published when an access token is about to be issued.
 * <p>
 * 即將簽發 Access Token 時發布。
 * <p>
 * It is published after the claims are decided and before the token is
 * signed, so it does not include the token itself, and it counts an attempt:
 * the token may still fail to be signed or its authorization to be saved.
 * On a refresh it is published inside the refresh transaction, unlike the
 * audit events, so a listener must not write to the authorization server
 * database (on SQLite it would wait for the transaction's own write lock).
 * <p>
 * 在 claim 決定之後、簽章之前發布，因此不包含 token 本身，且代表一次簽發嘗試：
 * token 之後仍可能簽章失敗，或其授權無法儲存。刷新時它在刷新的交易中發布（與
 * 稽核事件不同），因此 listener 不可寫入 Authorization Server 資料庫（在 SQLite
 * 上會等待該交易持有的寫入鎖）。
 *
 * @param clientId   the OAuth {@code client_id}, not the
 *                   {@code oauth2_registered_client.id}
 *                   <br>OAuth 的 {@code client_id}，不是
 *                   {@code oauth2_registered_client.id}
 * @param grantType  the grant type, for example {@code authorization_code}
 *                   <br>grant type，例如 {@code authorization_code}
 * @author Jacky
 * @since 2.1.0
 */
public record AccessTokenIssuedEvent(String clientId, String grantType) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     */
    public AccessTokenIssuedEvent {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(grantType, "grantType");
    }
}
