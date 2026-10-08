package jacky917.security.authorizationserver.observability;

import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyStatus;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link SigningKeyHealthIndicator}：沒有金鑰時 DOWN；輪換逾期以詳細資料標示。
 */
@DisplayName("SigningKeyHealthIndicator")
class SigningKeyHealthIndicatorTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private final SigningKeyStore keys = mock(SigningKeyStore.class);
    private final SigningKeyHealthIndicator indicator =
            new SigningKeyHealthIndicator(keys, Duration.ofDays(90), true, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    @DisplayName("沒有 ACTIVE 金鑰：DOWN")
    void downWithoutActiveKey() {
        when(keys.findActive()).thenReturn(Optional.empty());
        assertThat(indicator.health(true).getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    @DisplayName("使用 30 天：UP，未逾期；使用 93 天（超過 90 + 2 天）：仍 UP，標示逾期")
    void ageAndOverdue() {
        when(keys.findActive()).thenReturn(Optional.of(key(Duration.ofDays(30))));
        Health young = indicator.health(true);
        assertThat(young.getStatus()).isEqualTo(Status.UP);
        assertThat(young.getDetails()).containsEntry("ageDays", 30.0).containsEntry("rotationOverdue", false)
                .containsEntry("kid", "kid-1");
        when(keys.findActive()).thenReturn(Optional.of(key(Duration.ofDays(93))));
        assertThat(indicator.health(true).getDetails()).containsEntry("rotationOverdue", true);
    }

    @Test
    @DisplayName("停用輪換：使用再久也不標示逾期")
    void rotationDisabled() {
        SigningKeyHealthIndicator withoutRotation =
                new SigningKeyHealthIndicator(keys, Duration.ofDays(90), false, Clock.fixed(NOW, ZoneOffset.UTC));
        when(keys.findActive()).thenReturn(Optional.of(key(Duration.ofDays(400))));
        Health health = withoutRotation.health(true);
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).doesNotContainKey("rotationOverdue").containsEntry("rotationEnabled", false);
    }

    private static SigningKey key(Duration age) {
        Instant activated = NOW.minus(age);
        return new SigningKey("kid-1", "RS256", 3072, "{}", "secret", "v1", SigningKeyStatus.ACTIVE, activated,
                activated, null, null);
    }
}
