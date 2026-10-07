package jacky917.demo.authorizationserver.controller;

/**
 * Response body of the demo token endpoint.
 * <p>
 * Demo token 端點的回應內容。
 *
 * @param tokenType    the token type, always {@code Bearer}
 *                     <br>token 類型，固定為 {@code Bearer}
 * @param accessToken  the signed JWT access token
 *                     <br>已簽署的 JWT access token
 * @param expiresIn    the token lifetime in seconds
 *                     <br>token 有效秒數
 * @param issuer       the issuer ({@code iss}) written into the token
 *                     <br>寫入 token 的簽發者（{@code iss}）
 */
public record TokenResponse(
        String tokenType,
        String accessToken,
        long expiresIn,
        String issuer
) {
}

