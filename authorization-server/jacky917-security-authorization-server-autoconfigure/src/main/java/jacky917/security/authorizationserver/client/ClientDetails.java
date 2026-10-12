package jacky917.security.authorizationserver.client;

import org.jspecify.annotations.Nullable;

/**
 * What users see about a client on the consent page and the account page.
 * <p>
 * 使用者在同意畫面與帳號頁看到的 client 資訊。
 *
 * @param description       what the application does, or {@code null}
 *                          <br>應用程式的說明，或 {@code null}
 * @param logoUrl           the logo, or {@code null}
 *                          <br>Logo，或 {@code null}
 * @param homepageUrl       the home page, or {@code null}
 *                          <br>首頁，或 {@code null}
 * @param privacyPolicyUrl  the privacy policy; never {@code null} for a
 *                          third-party client
 *                          <br>隱私權政策；第三方 client 一定有值
 * @param termsUrl          the terms of service, or {@code null}
 *                          <br>服務條款，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record ClientDetails(@Nullable String description, @Nullable String logoUrl, @Nullable String homepageUrl,
                            @Nullable String privacyPolicyUrl, @Nullable String termsUrl) {

    /**
     * Details with nothing set.
     * <p>
     * 沒有任何資訊。
     */
    public static final ClientDetails NONE = new ClientDetails(null, null, null, null, null);
}
