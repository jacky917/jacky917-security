package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.ui.ExtendedModelMap;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 登入頁的第三方登入按鈕：可列出的 repository 自動顯示；無法列出時依 login.providers 顯示；
 * login.providers 指定不存在的 id 時啟動失敗。
 */
@DisplayName("LoginController 的第三方登入按鈕")
class LoginControllerTest {

    private static final ClientRegistration GOOGLE = registration("google", "Google");
    private static final ClientRegistration LINE = registration("line", "LINE");

    @Test
    @DisplayName("可列出的 repository（Spring Boot 預設）：全部顯示，依名稱排序（順序固定）")
    void listsIterableRepository() {
        for (InMemoryClientRegistrationRepository repository : List.of(
                new InMemoryClientRegistrationRepository(GOOGLE, LINE), new InMemoryClientRegistrationRepository(LINE, GOOGLE))) {
            assertThat(buttons(new AuthorizationServerProperties(), repository))
                    .containsExactly("/oauth2/authorization/google", "/oauth2/authorization/line");
        }
    }

    @Test
    @DisplayName("無法列出的 repository：依 login.providers 的順序顯示；未設定時沒有按鈕")
    void usesConfiguredProvidersForOpaqueRepository() {
        ClientRegistrationRepository opaque = id -> Map.of("google", GOOGLE, "line", LINE).get(id);
        assertThat(buttons(new AuthorizationServerProperties(), opaque)).isEmpty();

        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.getLogin().setProviders(List.of("line", "google"));
        assertThat(buttons(properties, opaque)).containsExactly("/oauth2/authorization/line", "/oauth2/authorization/google");
    }

    @Test
    @DisplayName("login.providers 指定不存在的 registration：啟動失敗")
    void unknownProviderFails() {
        AuthorizationServerProperties properties = new AuthorizationServerProperties();
        properties.getLogin().setProviders(List.of("github"));
        assertThatThrownBy(() -> new IdentityProviders(properties.getLogin().getProviders(),
                new InMemoryClientRegistrationRepository(GOOGLE)))
                .hasMessageContaining("github");
    }

    @SuppressWarnings("unchecked")
    private static List<String> buttons(AuthorizationServerProperties properties, ClientRegistrationRepository repository) {
        ExtendedModelMap model = new ExtendedModelMap();
        IdentityProviders providers = new IdentityProviders(properties.getLogin().getProviders(), repository);
        new LoginController(properties, providers, new jacky917.security.authorizationserver.account.UnavailableAccountMailer()).login(null, null, new MockHttpServletRequest(), model);
        return ((List<Map<String, String>>) model.get("providers")).stream().map(button -> button.get("url")).toList();
    }

    private static ClientRegistration registration(String id, String name) {
        return ClientRegistration.withRegistrationId(id).clientName(name).clientId(id + "-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://" + id + ".example.com/authorize").tokenUri("https://" + id + ".example.com/token")
                .build();
    }
}
