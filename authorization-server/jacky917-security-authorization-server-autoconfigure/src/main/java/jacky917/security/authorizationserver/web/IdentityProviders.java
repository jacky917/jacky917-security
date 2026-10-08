package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * The identity providers offered on the login and account pages, from
 * Spring Boot's {@code spring.security.oauth2.client.registration.*}.
 * <p>
 * 登入頁與帳號頁提供的身分提供者，取自 Spring Boot 的
 * {@code spring.security.oauth2.client.registration.*}。
 * <p>
 * With {@code login.providers} set, those registrations are listed in that
 * order. Otherwise every registration is listed by name, if the repository
 * can list them (Spring Boot's default can); a repository that cannot is
 * logged once and lists nothing. External logins still work then, but the
 * pages show no provider buttons and account linking is unavailable,
 * because {@link #find} only knows the listed providers; set
 * {@code login.providers} for such a repository.
 * <p>
 * 設定 {@code login.providers} 時，依該順序列出這些 registration。未設定時，
 * 若 repository 可以列出所有 registration（Spring Boot 的預設實作可以），依
 * 名稱排序列出全部；無法列出的 repository 只記錄一次警告，不列出任何提供者。
 * 此時第三方登入仍可使用，但頁面上沒有提供者按鈕，帳號連結也無法使用（因為
 * {@code find} 只認得列出的提供者）；這種 repository 請設定 {@code login.providers}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class IdentityProviders {

    private final List<Provider> providers;

    /**
     * Resolves the providers.
     * <p>
     * 解析提供者。
     *
     * @param configured  the registration ids from {@code login.providers},
     *                    or empty
     *                    <br>{@code login.providers} 中的 registration id，或空
     * @param repository  the client registrations, or {@code null} without
     *                    any
     *                    <br>client registration；沒有時為 {@code null}
     * @throws IllegalStateException if {@code configured} names a
     *         registration that does not exist
     *         <br>若 {@code configured} 指定了不存在的 registration
     */
    public IdentityProviders(List<String> configured, @Nullable ClientRegistrationRepository repository) {
        this.providers = resolve(configured, repository);
    }

    /**
     * Returns the providers in display order.
     * <p>
     * 依顯示順序回傳提供者。
     *
     * @return the providers; empty if there is none
     *         <br>提供者；沒有時為空
     */
    public List<Provider> list() {
        return providers;
    }

    /**
     * Finds a provider by its registration id.
     * <p>
     * 依 registration id 查詢提供者。
     *
     * @param registrationId  the registration id
     *                        <br>registration id
     * @return the provider, or empty if it is not offered
     *         <br>提供者；未提供時為空
     */
    public Optional<Provider> find(String registrationId) {
        return providers.stream().filter(provider -> provider.registrationId().equals(registrationId)).findFirst();
    }

    private static List<Provider> resolve(List<String> configured, @Nullable ClientRegistrationRepository repository) {
        List<Provider> found = new ArrayList<>();
        if (repository == null) {
            return found;
        }
        if (!configured.isEmpty()) {
            for (String registrationId : configured) {
                ClientRegistration client = repository.findByRegistrationId(registrationId);
                if (client == null) {
                    throw new IllegalStateException("login.providers contains " + registrationId
                            + ", but there is no client registration with that id");
                }
                found.add(new Provider(client.getRegistrationId(), client.getClientName()));
            }
        } else if (repository instanceof Iterable<?> registrations) {
            for (Object registration : registrations) {
                ClientRegistration client = (ClientRegistration) registration;
                found.add(new Provider(client.getRegistrationId(), client.getClientName()));
            }
            // Spring Boot 預設的 repository 以雜湊表保存，列出的順序不固定：依顯示名稱排序
            found.sort(Comparator.comparing(Provider::name, String.CASE_INSENSITIVE_ORDER));
        } else {
            // 無法列出的 repository（例如存放在資料庫中）：第三方登入仍可使用，但頁面上沒有按鈕、也無法連結帳號
            log.warn("The ClientRegistrationRepository cannot list its registrations, so the pages show no identity "
                    + "provider buttons and accounts cannot be linked; set " + AuthorizationServerProperties.PREFIX
                    + ".login.providers");
        }
        return List.copyOf(found);
    }

    /**
     * An identity provider offered to users.
     * <p>
     * 提供給使用者的身分提供者。
     *
     * @param registrationId  the registration id, also stored as
     *                        {@code user_federated_identity.provider}
     *                        <br>registration id，也是
     *                        {@code user_federated_identity.provider} 的值
     * @param name            the display name
     *                        <br>顯示名稱
     */
    public record Provider(String registrationId, String name) {
    }
}
