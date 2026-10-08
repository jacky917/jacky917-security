package jacky917.security.authorizationserver.federation;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Converts a GitHub user (detailed design §5.3). GitHub is not an OpenID
 * Connect provider, so its users need their own mapper.
 * <p>
 * 轉換 GitHub 的使用者（詳細設計 §5.3）。GitHub 不是 OpenID Connect 提供者，
 * 因此需要專屬的 mapper。
 * <ul>
 *   <li>The subject is GitHub's numeric user {@code id}; the login name can
 *       change and is never used as an identifier.
 *       <br>subject 為 GitHub 的數字使用者 {@code id}；登入名稱可能變更，
 *       不作為識別。</li>
 *   <li>The email is the primary, verified address from
 *       {@code GET /user/emails}, which needs the {@code user:email} scope.
 *       Without it, or when the call fails, the user has no email; the
 *       public profile email is never trusted.
 *       <br>Email 取自 {@code GET /user/emails} 中主要且已驗證的地址，需要
 *       {@code user:email} scope。沒有此 scope 或呼叫失敗時，使用者沒有
 *       Email；公開個人資料中的 Email 一律不採信。</li>
 * </ul>
 * It handles the registration {@code github} and any registration whose
 * user info endpoint is on {@code api.github.com}. The emails endpoint is the
 * user info endpoint followed by {@code /emails}, so GitHub Enterprise Server
 * works as well.
 * <p>
 * 處理 registration {@code github}，以及使用者資訊端點位於
 * {@code api.github.com} 的 registration。Email 端點為使用者資訊端點加上
 * {@code /emails}，因此也適用於 GitHub Enterprise Server。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class GitHubFederatedUserInfoMapper implements FederatedUserInfoMapper {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final @Nullable ClientRegistrationRepository registrations;
    private final RestClient restClient;

    /**
     * Creates the mapper with a client that times out after 5 seconds.
     * <p>
     * 建立 mapper，HTTP 呼叫 5 秒逾時。
     *
     * @param registrations  the client registrations, or {@code null} without
     *                       any
     *                       <br>client registration；沒有時為 {@code null}
     */
    public GitHubFederatedUserInfoMapper(@Nullable ClientRegistrationRepository registrations) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(TIMEOUT);
        factory.setReadTimeout(TIMEOUT);
        this.registrations = registrations;
        this.restClient = RestClient.builder().requestFactory(factory).build();
    }

    @Override
    public boolean supports(String registrationId) {
        ClientRegistration registration = registration(registrationId);
        if (registration == null) {
            return false;
        }
        String userInfo = registration.getProviderDetails().getUserInfoEndpoint().getUri();
        return "github".equals(registrationId)
                || (userInfo != null && "api.github.com".equals(URI.create(userInfo).getHost()));
    }

    @Override
    public FederatedUserInfo map(String registrationId, OAuth2User user, @Nullable OAuth2AccessToken accessToken) {
        Map<String, Object> attributes = user.getAttributes();
        Object id = attributes.get("id");
        if (id == null) {
            throw new IllegalArgumentException("The GitHub user of " + registrationId + " has no id");
        }
        String name = text(attributes.get("name"));
        String email = primaryVerifiedEmail(registrationId, accessToken);
        return new FederatedUserInfo(registrationId, String.valueOf(id), email, email != null,
                name != null ? name : text(attributes.get("login")), text(attributes.get("avatar_url")), null, attributes);
    }

    private @Nullable String primaryVerifiedEmail(String registrationId, @Nullable OAuth2AccessToken accessToken) {
        ClientRegistration registration = registration(registrationId);
        if (accessToken == null || registration == null) {
            return null;
        }
        String userInfo = registration.getProviderDetails().getUserInfoEndpoint().getUri();
        try {
            List<Map<String, Object>> emails = restClient.get().uri(userInfo + "/emails")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue())
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .retrieve().body(new ParameterizedTypeReference<>() { });
            if (emails == null) {
                return null;
            }
            return emails.stream()
                    .filter(entry -> Boolean.TRUE.equals(entry.get("primary")) && Boolean.TRUE.equals(entry.get("verified")))
                    .map(entry -> text(entry.get("email"))).filter(email -> email != null).findFirst().orElse(null);
        } catch (RestClientException ex) {
            // 通常是沒有 user:email scope：沒有 Email 仍可登入，只是不會用於帳號連結
            log.info("Cannot read the emails of a {} user; is the user:email scope requested? {}", registrationId,
                    ex.getMessage());
            return null;
        }
    }

    private @Nullable ClientRegistration registration(String registrationId) {
        return registrations == null ? null : registrations.findByRegistrationId(registrationId);
    }

    private static @Nullable String text(@Nullable Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString();
    }
}
