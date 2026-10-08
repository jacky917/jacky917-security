package jacky917.security.authorizationserver.support;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.UUID;

/**
 * Generates time-ordered UUIDs (version 7, RFC 9562) for primary keys, so
 * new rows are appended to the end of B-tree indexes.
 * <p>
 * 產生依時間排序的 UUID（第 7 版，RFC 9562）作為主鍵，新資料會加在 B-tree 索引的
 * 尾端。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class UuidV7 {

    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidV7() {
    }

    /**
     * Returns a new version 7 UUID for the clock's current time.
     * <p>
     * 以時鐘的目前時間產生新的第 7 版 UUID。
     *
     * @param clock  the clock that supplies the timestamp
     *               <br>提供時間戳記的時鐘
     * @return the UUID as a 36-character string
     *         <br>36 字元的 UUID 字串
     */
    public static String next(Clock clock) {
        long millis = clock.millis();
        long randomA = RANDOM.nextLong();
        long randomB = RANDOM.nextLong();
        long mostSignificant = (millis << 16) | 0x7000L | (randomA & 0x0FFFL);
        long leastSignificant = (randomB & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(mostSignificant, leastSignificant).toString();
    }
}
