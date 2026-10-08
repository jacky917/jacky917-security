package jacky917.security.authorizationserver.consent;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;

import java.time.Clock;

/**
 * Stores consents with another service and audits each change (phase 3 and
 * 4 design §6.2): saving publishes {@code CONSENT_GRANTED} and removing
 * publishes {@code CONSENT_REVOKED}, both for the user whose id is the
 * consent's principal name.
 * <p>
 * 以另一個服務儲存同意紀錄，並稽核每一次變更（第 3、4 階段設計 §6.2）：儲存時
 * 發布 {@code CONSENT_GRANTED}，刪除時發布 {@code CONSENT_REVOKED}；使用者即
 * 同意紀錄的 principal name（使用者 ID）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class AuditingAuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final OAuth2AuthorizationConsentService delegate;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param delegate  stores the consents
     *                  <br>儲存同意紀錄
     * @param events    publishes the audit events
     *                  <br>發布稽核事件
     * @param clock     the clock
     *                  <br>時鐘
     */
    public AuditingAuthorizationConsentService(OAuth2AuthorizationConsentService delegate,
                                               ApplicationEventPublisher events, Clock clock) {
        this.delegate = delegate;
        this.events = events;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        delegate.save(authorizationConsent);
        log.info("User {} consented to scopes {} of client {}", authorizationConsent.getPrincipalName(),
                authorizationConsent.getScopes(), authorizationConsent.getRegisteredClientId());
        publish(LoginAuditEventType.CONSENT_GRANTED, authorizationConsent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        delegate.remove(authorizationConsent);
        log.info("Consent of user {} to client {} removed", authorizationConsent.getPrincipalName(),
                authorizationConsent.getRegisteredClientId());
        publish(LoginAuditEventType.CONSENT_REVOKED, authorizationConsent);
    }

    @Override
    public @Nullable OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return delegate.findById(registeredClientId, principalName);
    }

    private void publish(LoginAuditEventType type, OAuth2AuthorizationConsent consent) {
        events.publishEvent(LoginAuditEvent.builder(type, clock.instant(), true)
                .userId(consent.getPrincipalName())
                .registeredClientId(consent.getRegisteredClientId())
                .currentRequest()
                .build());
    }
}
