package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyService;
import jacky917.security.authorizationserver.keys.SigningKeyStatus;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.maintenance.DataCleanup;
import jacky917.security.authorizationserver.maintenance.ScheduledJobLock;
import jacky917.security.authorizationserver.maintenance.SigningKeyRotation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwtException;
import tools.jackson.databind.JsonNode;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 排程工作（詳細設計 §5.7、§5.8）：金鑰輪換（T-KEY-02）、資料清理（T-CLEAN-01 與資料模型 §14.1）、排程鎖。
 * 測試直接呼叫工作，以可推移的時鐘模擬時間經過。
 */
abstract class AbstractMaintenanceIntegrationTest extends AbstractFlowIntegrationTest {

    @Autowired
    SigningKeyRotation rotation;

    @Autowired
    SigningKeyStore keyStore;

    @Autowired
    SigningKeyService keyService;

    @Autowired
    DataCleanup cleanup;

    @Autowired
    ScheduledJobLock lock;

    @Test
    @DisplayName("金鑰輪換：89 天時公開 NEXT（仍以舊金鑰簽章）→ 1 天後啟用（舊 token 仍可驗證）→ 36 分鐘後退役（T-KEY-02）")
    void rotatesTheSigningKey() throws Exception {
        createUser("rotation-user", null);
        String first = keyStore.findActive().orElseThrow().kid();
        String oldToken = logInAndExchangeCode("rotation-user").tokens().get("access_token").asString();
        rotation.rotate();
        assertThat(keyStore.findByStatus(SigningKeyStatus.NEXT)).as("還不到輪換時間").isEmpty();

        clock.advance(Duration.ofDays(89));
        rotation.rotate();
        String next = keyStore.findByStatus(SigningKeyStatus.NEXT).get(0).kid();
        assertThat(jwksKids()).containsExactlyInAnyOrder(first, next);
        assertThat(kidOf(logInAndExchangeCode("rotation-user"))).as("NEXT 尚未簽章").isEqualTo(first);
        rotation.rotate();
        assertThat(keyStore.findByStatus(SigningKeyStatus.NEXT)).as("公開期間未滿").hasSize(1);

        clock.advance(Duration.ofDays(1));
        rotation.rotate();
        assertThat(keyStore.findActive().orElseThrow().kid()).isEqualTo(next);
        assertThat(keyStore.findByStatus(SigningKeyStatus.RETIRING)).extracting(SigningKey::kid).containsExactly(first);
        assertThat(kidOf(logInAndExchangeCode("rotation-user"))).isEqualTo(next);
        assertThat(jwtDecoder.decode(oldToken).getSubject()).as("舊金鑰簽的 token 仍可驗證").isNotNull();

        clock.advance(Duration.ofMinutes(36));
        rotation.rotate();
        assertThat(keyStore.findByStatus(SigningKeyStatus.RETIRED)).extracting(SigningKey::kid).contains(first);
        assertThat(jwksKids()).containsExactly(next);
        assertThatThrownBy(() -> jwtDecoder.decode(oldToken)).as("退役後不再公開").isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("清理授權：token 全部過期的刪除；沒有 token 的授權超過 1 小時才刪除（等待同意中的不刪）（T-CLEAN-01）")
    void deletesExpiredAuthorizations() throws Exception {
        createUser("cleanup-user", null);
        LoggedIn expired = logInAndExchangeCode("cleanup-user");
        LoggedIn alive = logInAndExchangeCode("cleanup-user");
        Timestamp past = Timestamp.from(Instant.now().minusSeconds(60));
        jdbc.sql("UPDATE oauth2_authorization SET authorization_code_expires_at = :past, access_token_expires_at = :past, "
                        + "refresh_token_expires_at = :past, oidc_id_token_expires_at = :past WHERE id = "
                        + "(SELECT authorization_id FROM session_authorization WHERE session_id = :asid)")
                .param("past", past).param("asid", expired.asid()).update();
        String recentPending = pendingAuthorization(alive.asid(), Duration.ofMinutes(10));
        String oldPending = pendingAuthorization(alive.asid(), Duration.ofHours(2));

        assertThat(cleanup.deleteExpiredAuthorizations()).isEqualTo(2);
        assertThat(authorizationCount(expired.asid())).isZero();
        assertThat(exists(oldPending)).isFalse();
        assertThat(exists(recentPending)).as("可能正在等使用者同意").isTrue();
        assertThat(authorizationCount(alive.asid())).as("有效的授權與等待中的授權").isEqualTo(2);
    }

    @Test
    @DisplayName("清理登入 Session：過期的改為 EXPIRED 並刪除授權；撤銷或過期超過 30 天的刪除")
    void expiresAndDeletesSessions() throws Exception {
        createUser("session-cleanup", null);
        LoggedIn expiring = logInAndExchangeCode("session-cleanup");
        LoggedIn oldRevoked = logInAndExchangeCode("session-cleanup");
        LoggedIn recentRevoked = logInAndExchangeCode("session-cleanup");
        Instant now = clock.instant();
        jdbc.sql("UPDATE auth_session SET expires_at = :at WHERE session_id = :id")
                .param("at", Timestamp.from(now.minusSeconds(1))).param("id", expiring.asid()).update();
        revoke(oldRevoked.asid(), now.minus(Duration.ofDays(31)));
        revoke(recentRevoked.asid(), now.minus(Duration.ofDays(1)));

        assertThat(cleanup.expireSessions()).isGreaterThanOrEqualTo(1);
        assertSession(expiring.asid(), "EXPIRED", null);
        assertThat(authorizationCount(expiring.asid())).isZero();
        assertThat(cleanup.deleteOldSessions()).isEqualTo(1);
        assertThat(sessionExists(oldRevoked.asid())).isFalse();
        assertThat(sessionExists(recentRevoked.asid())).isTrue();

        clock.advance(Duration.ofDays(31));
        assertThat(cleanup.deleteOldSessions()).as("過期超過 30 天的 EXPIRED 與 1 天前撤銷的").isGreaterThanOrEqualTo(2);
        assertThat(sessionExists(expiring.asid())).isFalse();
    }

    @Test
    @DisplayName("清理 Refresh Token 歷史、操作 token、稽核紀錄、退役超過一年的金鑰；以小批次刪除也會全部刪完")
    void deletesOtherExpiredData() {
        String userId = createUser("other-cleanup", null);
        Instant now = clock.instant();
        for (int i = 0; i < 5; i++) {
            history("expired-" + i, now.minusSeconds(1));
        }
        history("alive", now.plusSeconds(3600));
        DataCleanup smallBatches = new DataCleanup(jdbc, keyStore, 2, Duration.ofDays(180), Duration.ofDays(730), clock);
        assertThat(smallBatches.deleteExpiredRefreshTokenHistory()).isEqualTo(5);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM refresh_token_history").query(Integer.class).single()).isEqualTo(1);

        actionToken(userId, now.minus(Duration.ofDays(8)));
        actionToken(userId, now.minus(Duration.ofDays(6)));
        assertThat(cleanup.deleteOldActionTokens()).isEqualTo(1);

        audit(userId, now.minus(Duration.ofDays(181)));
        audit(userId, now.minus(Duration.ofDays(179)));
        assertThat(cleanup.deleteOldAudits()).isEqualTo(1);

        SigningKey retired = keyService.generate(SigningKeyStatus.NEXT);
        keyStore.save(new SigningKey(retired.kid(), retired.algorithm(), retired.keySize(), retired.publicJwk(),
                retired.privateKeyEncrypted(), retired.encryptionKeyId(), SigningKeyStatus.RETIRED,
                now.minus(Duration.ofDays(500)), null, null, now.minus(Duration.ofDays(366))));
        assertThat(cleanup.deleteOldSigningKeys()).isEqualTo(1);
    }

    @Test
    @DisplayName("排程鎖：持有期間其他呼叫取得不到；持有時間結束後可以再取得")
    void scheduledJobLock() {
        String name = "test-" + UUID.randomUUID();
        assertThat(lock.tryLock(name, Duration.ofMinutes(10))).isTrue();
        assertThat(lock.tryLock(name, Duration.ofMinutes(10))).isFalse();
        clock.advance(Duration.ofMinutes(11));
        assertThat(lock.tryLock(name, Duration.ofMinutes(10))).isTrue();
    }

    private java.util.List<String> jwksKids() throws Exception {
        keyService.evictCache();
        JsonNode jwks = JSON.readTree(mockMvc.perform(get("/oauth2/jwks")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        java.util.List<String> kids = new java.util.ArrayList<>();
        jwks.get("keys").forEach(key -> kids.add(key.get("kid").asString()));
        return kids;
    }

    private String kidOf(LoggedIn result) {
        return (String) jwtDecoder.decode(result.tokens().get("access_token").asString()).getHeaders().get("kid");
    }

    private String pendingAuthorization(String asid, Duration age) {
        String id = UUID.randomUUID().toString();
        String client = clients.findByClientId("web-bff").getId();
        String user = jdbc.sql("SELECT user_id FROM auth_session WHERE session_id = :id").param("id", asid)
                .query(String.class).single();
        jdbc.sql("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type) "
                        + "VALUES (:id, :client, :user, 'authorization_code')")
                .param("id", id).param("client", client).param("user", user).update();
        jdbc.sql("INSERT INTO session_authorization (authorization_id, session_id, registered_client_id, created_at) "
                        + "VALUES (:id, :asid, :client, :at)")
                .param("id", id).param("asid", asid).param("client", client)
                .param("at", Timestamp.from(clock.instant().minus(age))).update();
        return id;
    }

    private boolean exists(String authorizationId) {
        return jdbc.sql("SELECT COUNT(*) FROM oauth2_authorization WHERE id = :id").param("id", authorizationId)
                .query(Integer.class).single() > 0;
    }

    private boolean sessionExists(String asid) {
        return jdbc.sql("SELECT COUNT(*) FROM auth_session WHERE session_id = :id").param("id", asid)
                .query(Integer.class).single() > 0;
    }

    private void revoke(String asid, Instant at) {
        jdbc.sql("UPDATE auth_session SET status = 'REVOKED', revoked_at = :at, revoke_reason = 'LOGOUT' "
                + "WHERE session_id = :id").param("at", Timestamp.from(at)).param("id", asid).update();
    }

    private void history(String token, Instant expiresAt) {
        jdbc.sql("INSERT INTO refresh_token_history (token_hash, authorization_id, registered_client_id, issued_at, "
                        + "rotated_at, expires_at) VALUES (:hash, 'a', 'c', :at, :at, :expires)")
                .param("hash", jacky917.security.authorizationserver.support.Hashes.sha256Hex(token + UUID.randomUUID()))
                .param("at", Timestamp.from(clock.instant())).param("expires", Timestamp.from(expiresAt)).update();
    }

    private void actionToken(String userId, Instant expiresAt) {
        jdbc.sql("INSERT INTO user_action_token (token_hash, user_id, purpose, expires_at, created_at) "
                        + "VALUES (:hash, :user, 'LINK_ACCOUNT', :expires, :created)")
                .param("hash", jacky917.security.authorizationserver.support.Hashes.sha256Hex(UUID.randomUUID().toString()))
                .param("user", userId).param("expires", Timestamp.from(expiresAt))
                .param("created", Timestamp.from(expiresAt.minus(Duration.ofMinutes(10)))).update();
    }

    private void audit(String userId, Instant at) {
        jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, user_id, success) VALUES (:at, 'LOGIN', :user, :ok)")
                .param("at", Timestamp.from(at)).param("user", userId).param("ok", true).update();
    }
}
