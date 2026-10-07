package jacky917.demo.authorizationserver.controller;

import java.util.List;

/**
 * Request body for the demo token endpoint.
 * <p>
 * Demo token 端點的請求內容。
 *
 * @param username          the subject of the token; must not be blank
 *                          <br>token 的主體（{@code sub}），不可為空白
 * @param password          the password; must be {@code password}
 *                          <br>密碼，必須為 {@code password}
 * @param roles             the roles to include, or {@code null} for the
 *                          default
 *                          <br>要放入的角色；{@code null} 表示使用預設值
 * @param permissions       the permissions to include, or {@code null} for
 *                          the default
 *                          <br>要放入的權限；{@code null} 表示使用預設值
 * @param scp               the scopes to include, or {@code null} for the
 *                          default
 *                          <br>要放入的 scope；{@code null} 表示使用預設值
 * @param sid               the session ID claim, or {@code null} for the
 *                          default
 *                          <br>session ID claim；{@code null} 表示使用預設值
 * @param expiresInSeconds  the token lifetime in seconds, or {@code null}
 *                          for the default
 *                          <br>token 有效秒數；{@code null} 表示使用預設值
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

