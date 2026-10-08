package jacky917.security.authorizationserver.token;

/**
 * Published when an access token is about to be issued.
 * <p>
 * 即將簽發 Access Token 時發布。
 * <p>
 * It is published after the claims are decided and before the token is
 * signed, so it does not include the token itself.
 * <p>
 * 在 claim 決定之後、簽章之前發布，因此不包含 token 本身。
 *
 * @param clientId   the client id
 *                   <br>client id
 * @param grantType  the grant type, for example {@code authorization_code}
 *                   <br>grant type，例如 {@code authorization_code}
 * @author Jacky
 * @since 2.1.0
 */
public record AccessTokenIssuedEvent(String clientId, String grantType) {
}
