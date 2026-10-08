package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.client.ClientDetails;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.consent.ScopeDescriptions;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The consent page of third-party clients (phase 3 and 4 design §6.2).
 * Spring Authorization Server sends the browser here when a client that
 * requires consent asks for scopes the user has not consented to.
 * <p>
 * 第三方 client 的同意畫面（第 3、4 階段設計 §6.2）。需要同意的 client 要求
 * 使用者尚未同意的 scope 時，Spring Authorization Server 把瀏覽器導向此頁。
 * <ul>
 *   <li>The page shows the client's name, logo, description and links, the
 *       scopes to consent to with their names and descriptions, and the
 *       scopes consented to before.
 *       <br>頁面顯示 client 的名稱、Logo、說明與連結、要同意的 scope 及其
 *       名稱與說明，以及先前已同意的 scope。</li>
 *   <li>"Allow" posts the shown scopes and those that need no consent to
 *       {@code /oauth2/authorize}; "Deny" posts none, and the client gets
 *       {@code access_denied}.
 *       <br>「允許」把顯示的 scope 與不需要同意的 scope 送到
 *       {@code /oauth2/authorize}；「拒絕」不送任何 scope，client 收到
 *       {@code access_denied}。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class ConsentController {

    /**
     * The path of the consent page.
     * <p>
     * 同意畫面的路徑。
     */
    public static final String CONSENT_PATH = "/oauth2/consent";

    private static final String[] PAGE_KEYS = {"consent.title", "consent.requested", "consent.previous",
            "consent.allow", "consent.deny", "consent.homepage", "consent.privacy", "consent.terms",
            "consent.hint"};

    private final RegisteredClientRepository clients;
    private final ClientProfileRepository profiles;
    private final OAuth2AuthorizationConsentService consents;
    private final ScopeDescriptions scopes;
    private final PageSupport page;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @param clients     finds the client that asks for consent
     *                    <br>找到要求同意的 client
     * @param profiles    what users see about the client
     *                    <br>使用者看到的 client 資訊
     * @param consents    the scopes consented to before
     *                    <br>先前已同意的 scope
     * @param scopes      describes the scopes
     *                    <br>描述 scope
     */
    public ConsentController(AuthorizationServerProperties properties, RegisteredClientRepository clients,
                             ClientProfileRepository profiles, OAuth2AuthorizationConsentService consents,
                             ScopeDescriptions scopes) {
        this.clients = clients;
        this.profiles = profiles;
        this.consents = consents;
        this.scopes = scopes;
        this.page = new PageSupport(properties.getBranding());
    }

    /**
     * Shows the consent page.
     * <p>
     * 顯示同意畫面。
     *
     * @param clientId        the client asking for consent
     *                        <br>要求同意的 client
     * @param scope           the requested scopes, separated by spaces
     *                        <br>要求的 scope，以空白分隔
     * @param state           the state of the authorization request, sent
     *                        back with the decision
     *                        <br>授權請求的 state，與決定一起送回
     * @param authentication  the logged-in user; the name is the user id
     *                        <br>已登入的使用者，名稱即使用者 ID
     * @param request         the current request, for its language
     *                        <br>目前的請求，用於判斷語言
     * @param model           the view model
     *                        <br>畫面資料
     * @return the consent view
     *         <br>同意畫面
     * @throws ResponseStatusException {@code 400} if the client is unknown
     *         or not active
     *         <br>client 不存在或未啟用時為 {@code 400}
     */
    @GetMapping(CONSENT_PATH)
    public String consent(@RequestParam("client_id") String clientId, @RequestParam(required = false) @Nullable String scope,
                          @RequestParam String state, Authentication authentication, HttpServletRequest request,
                          Model model) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown client");
        }
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        OAuth2AuthorizationConsent previous = consents.findById(client.getId(), authentication.getName());
        Set<String> consented = previous == null ? Set.of() : previous.getScopes();
        Set<String> requested = new LinkedHashSet<>(scope == null ? List.of() : Arrays.asList(scope.split(" ")));
        requested.remove("");
        List<ScopeDescriptions.Scope> toConsent = new ArrayList<>();
        List<ScopeDescriptions.Scope> alreadyConsented = new ArrayList<>();
        List<String> automatic = new ArrayList<>();
        for (ScopeDescriptions.Scope described : scopes.describe(requested)) {
            if (OidcScopes.OPENID.equals(described.code()) || !described.consentRequired()) {
                // Spring Authorization Server 自動核准 openid；其他不需要同意的 scope 隨「允許」一起送出
                automatic.add(described.code());
            } else if (consented.contains(described.code())) {
                alreadyConsented.add(described);
            } else {
                toConsent.add(described);
            }
        }
        ClientDetails details = profiles.details(client.getId()).orElse(ClientDetails.NONE);
        String name = profiles.find(client.getId()).map(profile -> profile.displayName())
                .orElse(client.getClientName());
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", name);
        model.addAttribute("client", details);
        model.addAttribute("heading", page.message("consent.heading", new Object[]{name}, locale));
        model.addAttribute("state", state);
        model.addAttribute("scopes", toConsent);
        model.addAttribute("previousScopes", alreadyConsented);
        model.addAttribute("automaticScopes", automatic);
        return "jacky917/consent";
    }
}
