package jacky917.demo.authorizationserver.controller;

import java.util.List;

/**
 * Demo Token 申請請求。
 */
public record TokenRequest(
        String username,
        String password,
        List<String> roles,
        List<String> permissions,
        List<String> scp,
        String sid,
        Long expiresInSeconds
) {
}

