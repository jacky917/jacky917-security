package jacky917.security.authorizationserver.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("UuidV7（RFC 9562）")
class UuidV7Test {

    private static final Instant T = Instant.parse("2026-10-08T00:00:00.123Z");

    @Test
    @DisplayName("版本 7、variant 為 RFC 9562；前 48 位元為毫秒時間戳記")
    void layout() {
        UUID uuid = UUID.fromString(UuidV7.next(Clock.fixed(T, ZoneOffset.UTC)));
        assertThat(uuid.version()).isEqualTo(7);
        assertThat(uuid.variant()).isEqualTo(2);
        assertThat(uuid.getMostSignificantBits() >>> 16).isEqualTo(T.toEpochMilli());
    }

    @Test
    @DisplayName("不同毫秒依時間排序（字串比較即可）；同一毫秒內不重複")
    void orderingAndUniqueness() {
        String earlier = UuidV7.next(Clock.fixed(T, ZoneOffset.UTC));
        String later = UuidV7.next(Clock.fixed(T.plusMillis(1), ZoneOffset.UTC));
        assertThat(later).isGreaterThan(earlier);

        Set<String> ids = new HashSet<>();
        Clock sameMillisecond = Clock.fixed(T, ZoneOffset.UTC);
        for (int i = 0; i < 10_000; i++) {
            ids.add(UuidV7.next(sameMillisecond));
        }
        assertThat(ids).hasSize(10_000);
    }
}
