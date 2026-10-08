package jacky917.security.authorizationserver.token;

import jacky917.security.authorizationserver.client.ClientProfile;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jacky917.security.core.Jacky917ClaimNames;
import jacky917.security.core.TrustLevel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Adds the jacky917 claims to access tokens and ID tokens (detailed design
 * §4.2, §4.3).
 * <p>
 * 在 Access Token 與 ID Token 中加入 jacky917 的 claim（詳細設計 §4.2、§4.3）。
 * <ul>
 *   <li>Access tokens: {@code aud} from {@link AudienceResolver},
 *       {@code client_id}; for users also {@code asid}, {@code idp},
 *       {@code roles} (first-party clients only), and
 *       {@code permissions}.
 *       <br>Access Token：{@code aud}（由 {@link AudienceResolver} 決定）、
 *       {@code client_id}；使用者的 token 另有 {@code asid}、{@code idp}、
 *       {@code roles}（只給第一方 client）與 {@code permissions}。</li>
 *   <li>ID tokens: {@code amr}, and user details when the {@code profile}
 *       or {@code email} scope was granted. Roles and permissions are never
 *       put in ID tokens.
 *       <br>ID Token：{@code amr}，以及授權 {@code profile}、{@code email}
 *       scope 時的使用者資料。角色與權限一律不放入 ID Token。</li>
 * </ul>
 * Roles and permissions are read from the database for every token,
 * including refreshes (D18). A user token is refused with
 * {@code invalid_grant} when its login session is no longer active or the
 * user is no longer {@code ACTIVE}. A temporary lock after failed logins
 * blocks only password logins, not the sessions that already exist.
 * <p>
 * 角色與權限在每次簽發 token（包含刷新）時都從資料庫讀取（D18）。登入 Session
 * 已失效，或使用者已不是 {@code ACTIVE} 時，以 {@code invalid_grant} 拒絕簽發。
 * 登入失敗造成的暫時鎖定只阻擋密碼登入，不影響已存在的 Session。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class Jacky917TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final AudienceResolver audienceResolver;
    private final AuthorityResolver authorityResolver;
    private final ClientProfileRepository clientProfiles;
    private final SessionAuthorizationRepository links;
    private final AuthSessionService sessions;
    private final UserAccountService users;
    private final List<TokenClaimsContributor> contributors;
    private final Clock clock;

    /**
     * Creates the customizer.
     * <p>
     * 建立 customizer。
     *
     * @param audienceResolver   decides {@code aud}
     *                           <br>決定 {@code aud}
     * @param authorityResolver  decides roles and permissions
     *                           <br>決定角色與權限
     * @param clientProfiles     the client profiles, for the trust level
     *                           <br>client 資料，用於取得信任等級
     * @param links              the authorization links, for the login session
     *                           <br>授權連結，用於取得登入 Session
     * @param sessions           the login sessions
     *                           <br>登入 Session
     * @param users              the user accounts
     *                           <br>使用者帳號
     * @param contributors       application claims, called last
     *                           <br>應用程式的 claim，最後呼叫
     * @param clock              the clock for status checks
     *                           <br>判斷狀態所用的時鐘
     */
    public Jacky917TokenCustomizer(AudienceResolver audienceResolver, AuthorityResolver authorityResolver,
                                   ClientProfileRepository clientProfiles, SessionAuthorizationRepository links,
                                   AuthSessionService sessions, UserAccountService users,
                                   List<TokenClaimsContributor> contributors, Clock clock) {
        this.audienceResolver = audienceResolver;
        this.authorityResolver = authorityResolver;
        this.clientProfiles = clientProfiles;
        this.links = links;
        this.sessions = sessions;
        this.users = users;
        this.contributors = List.copyOf(contributors);
        this.clock = clock;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        boolean accessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
        boolean idToken = OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue());
        if (!accessToken && !idToken) {
            return;
        }
        RegisteredClient client = context.getRegisteredClient();
        Set<String> scopes = context.getAuthorizedScopes();
        JwtClaimsSet.Builder claims = context.getClaims();
        if (accessToken) {
            claims.audience(audienceResolver.resolve(client, scopes));
            claims.claim(Jacky917ClaimNames.CLIENT_ID, client.getClientId());
        }
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            contribute(context, Optional.empty());
            return;
        }

        String userId = context.getPrincipal().getName();
        Instant now = clock.instant();
        // 同一次 token 請求會依序簽發 Access Token 與 ID Token：使用者與登入 Session 只查一次
        UserAccount user = perRequest("user:" + userId, () -> users.findById(userId))
                // 暫時鎖定不阻擋簽發：否則任何人故意輸錯密碼，就能讓帳號持有人所有裝置的刷新失敗
                .filter(account -> account.status() == UserStatus.ACTIVE)
                .orElseThrow(() -> refuse("user " + userId + " is not active"));
        OAuth2Authorization authorization = context.getAuthorization();
        AuthSession session = perRequest("session:" + (authorization == null ? "" : authorization.getId()),
                () -> loginSession(authorization))
                .filter(found -> found.isUsable(now))
                .orElseThrow(() -> refuse("the login session of user " + userId + " is not active"));

        if (accessToken) {
            TrustLevel trustLevel = clientProfiles.find(client.getId()).map(ClientProfile::trustLevel)
                    // 沒有 client 資料的 client（不是由本 starter 註冊）視為第三方：最小權限
                    .orElse(TrustLevel.THIRD_PARTY);
            ResolvedAuthorities authorities = authorityResolver.resolve(userId, client, trustLevel, scopes);
            claims.claim(Jacky917ClaimNames.ASID, session.sessionId());
            claims.claim(Jacky917ClaimNames.IDP, session.idp());
            if (trustLevel == TrustLevel.FIRST_PARTY) {
                claims.claim(Jacky917ClaimNames.ROLES, List.copyOf(authorities.roles()));
            }
            claims.claim(Jacky917ClaimNames.PERMISSIONS, List.copyOf(authorities.permissions()));
        } else {
            // sid、nonce、azp、auth_time 由 Spring Security 設定，不覆寫（OIDC 登出驗證需要）
            claims.claim("amr", List.of(session.amr().split(",")));
            if (scopes.contains(OidcScopes.PROFILE)) {
                putIfPresent(claims, "name", user.displayName());
                putIfPresent(claims, "picture", user.avatarUrl());
                putIfPresent(claims, "locale", user.locale());
            }
            if (scopes.contains(OidcScopes.EMAIL) && user.emailVerified() && user.email() != null) {
                claims.claim("email", user.email());
                claims.claim("email_verified", true);
            }
        }
        contribute(context, Optional.of(user));
    }

    /**
     * Reuses a lookup within the current HTTP request; outside a request it
     * always runs the lookup. Nothing is kept across requests, so changes
     * apply at the next token request (D18).
     * <p>
     * 在目前的 HTTP 請求中重複使用查詢結果；沒有請求時一律重新查詢。不會跨請求
     * 保留，因此變更會在下一次 token 請求生效（D18）。
     */
    @SuppressWarnings("unchecked")
    private static <T> T perRequest(String key, Supplier<T> lookup) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return lookup.get();
        }
        String name = Jacky917TokenCustomizer.class.getName() + "." + key;
        Object cached = attributes.getAttribute(name, RequestAttributes.SCOPE_REQUEST);
        if (cached == null) {
            cached = lookup.get();
            attributes.setAttribute(name, cached, RequestAttributes.SCOPE_REQUEST);
        }
        return (T) cached;
    }

    private Optional<AuthSession> loginSession(OAuth2Authorization authorization) {
        if (authorization == null) {
            return Optional.empty();
        }
        return links.findSessionId(authorization.getId()).flatMap(sessions::find);
    }

    private void contribute(JwtEncodingContext context, Optional<UserAccount> user) {
        contributors.forEach(contributor -> contributor.contribute(context, user));
        // Spring Security 把 token 的 claim 存入 oauth2_authorization，刷新時再以型別允許清單讀回；
        // List.of() 等不可變集合不在清單中，存入後授權會無法讀取（刷新失敗），因此一律換成可序列化的集合
        context.getClaims().claims(all -> all.replaceAll((name, value) -> serializable(value)));
    }

    private static Object serializable(Object value) {
        if (value instanceof Collection<?> collection && !(value instanceof ArrayList<?>)) {
            List<Object> copy = new ArrayList<>();
            collection.forEach(item -> copy.add(serializable(item)));
            return copy;
        }
        if (value instanceof Map<?, ?> map && !(value instanceof LinkedHashMap<?, ?>)) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            map.forEach((key, item) -> copy.put(key, serializable(item)));
            return copy;
        }
        return value;
    }

    private static void putIfPresent(JwtClaimsSet.Builder claims, String name, String value) {
        if (value != null && !value.isBlank()) {
            claims.claim(name, value);
        }
    }

    private static OAuth2AuthenticationException refuse(String reason) {
        // 不揭露原因（詳細設計 §7.1），原因只寫入日誌
        log.info("Refusing to issue a token: {}", reason);
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
    }
}
