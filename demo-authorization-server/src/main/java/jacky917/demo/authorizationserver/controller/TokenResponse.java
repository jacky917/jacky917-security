package jacky917.demo.authorizationserver.controller;

/**
 * Demo Token 回應。
 */
public record TokenResponse(
        String tokenType,
        String accessToken,
        long expiresIn,
        String issuer
) {
}

