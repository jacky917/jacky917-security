package jacky917.security.authorizationserver.maintenance;

import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyService;
import jacky917.security.authorizationserver.keys.SigningKeyStatus;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link SigningKeyRotation} 的單元測試：替換到一半失敗時整個回滾、沒有 ACTIVE 金鑰時補建、退役時間依 Access Token
 * 有效期計算。完整的輪換流程由排程工作整合測試（T-KEY-02）涵蓋。
 */
@DisplayName("SigningKeyRotation")
class SigningKeyRotationTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final Duration ROTATION = Duration.ofDays(90);
    private static final Duration ANNOUNCE = Duration.ofDays(1);

    private SigningKeyStore store;
    private SigningKeyService keys;
    private final SimpleTransactionStatus transaction = new SimpleTransactionStatus();
    private final TransactionOperations transactions = new TransactionOperations() {
        @Override
        public <T> T execute(TransactionCallback<T> action) {
            return action.doInTransaction(transaction);
        }
    };

    @BeforeEach
    void setUp() {
        store = mock(SigningKeyStore.class);
        keys = mock(SigningKeyService.class);
    }

    @Test
    @DisplayName("沒有 ACTIVE 金鑰：補建一把，不做其他步驟")
    void createsAMissingActiveKey() {
        when(store.findActive()).thenReturn(Optional.empty());
        rotation(Duration.ofMinutes(30)).rotate();
        verify(keys).ensureActiveKey();
        verify(store).findActive();
        verifyNoMoreInteractions(store);
    }

    @Test
    @DisplayName("替換時新金鑰已被其他實例改變：交易回滾，不清除快取（不會留下沒有 ACTIVE 金鑰的狀態）")
    void rollsBackAHalfDoneSwap() {
        SigningKey active = key("old", SigningKeyStatus.ACTIVE, NOW.minus(ROTATION), null);
        SigningKey next = key("new", SigningKeyStatus.NEXT, NOW.minus(ANNOUNCE), null);
        when(store.findActive()).thenReturn(Optional.of(active));
        when(store.findByStatus(SigningKeyStatus.NEXT)).thenReturn(List.of(next));
        when(store.findByStatus(SigningKeyStatus.RETIRING)).thenReturn(List.of());
        when(store.transition("old", SigningKeyStatus.ACTIVE, SigningKeyStatus.RETIRING, NOW)).thenReturn(true);
        when(store.transition("new", SigningKeyStatus.NEXT, SigningKeyStatus.ACTIVE, NOW)).thenReturn(false);

        rotation(Duration.ofMinutes(30)).rotate();

        assertThat(transaction.isRollbackOnly()).isTrue();
        verify(keys, never()).evictCache();
    }

    @Test
    @DisplayName("公開期間結束：舊金鑰改為 RETIRING、NEXT 改為 ACTIVE，並清除快取")
    void promotesTheNextKey() {
        SigningKey active = key("old", SigningKeyStatus.ACTIVE, NOW.minus(ROTATION), null);
        SigningKey next = key("new", SigningKeyStatus.NEXT, NOW.minus(ANNOUNCE), null);
        when(store.findActive()).thenReturn(Optional.of(active));
        when(store.findByStatus(SigningKeyStatus.NEXT)).thenReturn(List.of(next));
        when(store.findByStatus(SigningKeyStatus.RETIRING)).thenReturn(List.of());
        when(store.transition(any(), any(), any(), eq(NOW))).thenReturn(true);

        rotation(Duration.ofMinutes(30)).rotate();

        assertThat(transaction.isRollbackOnly()).isFalse();
        verify(keys).evictCache();
    }

    @Test
    @DisplayName("Access Token 有效期 60 分鐘：RETIRING 滿 65 分鐘才退役，64 分鐘時不退役")
    void retiresAfterTheLongestTokenPlusMargin() {
        SigningKey active = key("current", SigningKeyStatus.ACTIVE, NOW.minus(Duration.ofDays(10)), null);
        when(store.findActive()).thenReturn(Optional.of(active));
        when(store.findByStatus(SigningKeyStatus.NEXT)).thenReturn(List.of());
        SigningKey young = key("young", SigningKeyStatus.RETIRING, NOW.minus(Duration.ofDays(91)),
                NOW.minus(Duration.ofMinutes(64)));
        SigningKey old = key("old", SigningKeyStatus.RETIRING, NOW.minus(Duration.ofDays(91)),
                NOW.minus(Duration.ofMinutes(65)));
        when(store.findByStatus(SigningKeyStatus.RETIRING)).thenReturn(List.of(young, old));
        when(store.transition("old", SigningKeyStatus.RETIRING, SigningKeyStatus.RETIRED, NOW)).thenReturn(true);

        rotation(Duration.ofMinutes(60)).rotate();

        verify(store, never()).transition(eq("young"), any(), any(), any());
        verify(store).transition("old", SigningKeyStatus.RETIRING, SigningKeyStatus.RETIRED, NOW);
        verify(keys).evictCache();
    }

    private SigningKeyRotation rotation(Duration accessTokenTtl) {
        return new SigningKeyRotation(store, keys, transactions, ROTATION, ANNOUNCE, accessTokenTtl,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static SigningKey key(String kid, SigningKeyStatus status, Instant activatedAt, Instant retiringAt) {
        return new SigningKey(kid, "RS256", 3072, "{}", "secret", "v1", status, activatedAt, activatedAt, retiringAt,
                null);
    }
}
