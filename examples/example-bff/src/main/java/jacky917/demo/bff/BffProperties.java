package jacky917.demo.bff;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where the example BFF finds the other services, bound from
 * {@code demo.*}.
 * <p>
 * 範例 BFF 連線的其他服務，綁定自 {@code demo.*}。
 *
 * @param authorizationServerUrl  the login service, for logout
 *                                <br>登入服務，用於登出
 * @param resourceServerUrl       the API called with the access token
 *                                <br>以 Access Token 呼叫的 API
 */
@ConfigurationProperties("demo")
public record BffProperties(String authorizationServerUrl, String resourceServerUrl) {
}
