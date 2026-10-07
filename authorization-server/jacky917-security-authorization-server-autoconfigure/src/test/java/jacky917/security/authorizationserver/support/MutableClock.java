package jacky917.security.authorizationserver.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 測試用的時鐘：預設跟著系統時間走，可以往後推移，讓到期相關的行為可以確定地測試。
 * 只影響本專案以 {@code Clock} Bean 取得的時間；Spring Security 自己簽發與驗證 token 時使用系統時間。
 */
public final class MutableClock extends Clock {

    private volatile Duration offset = Duration.ZERO;

    /**
     * 往後推移時間。
     */
    public void advance(Duration duration) {
        offset = offset.plus(duration);
    }

    /**
     * 回到系統時間。
     */
    public void reset() {
        offset = Duration.ZERO;
    }

    @Override
    public Instant instant() {
        return Instant.now().plus(offset);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException();
    }
}
