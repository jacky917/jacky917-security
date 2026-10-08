package jacky917.security.authorizationserver.observability;

import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

/**
 * Reports whether the authorization server can sign tokens (detailed design
 * §8.4): {@code DOWN} when there is no {@code ACTIVE} signing key.
 * <p>
 * 回報 Authorization Server 能否簽發 token（詳細設計 §8.4）：沒有
 * {@code ACTIVE} 簽章金鑰時為 {@code DOWN}。
 * <p>
 * The details show the key id, the algorithm, the age in days, and, when
 * the rotation is turned on, whether it is overdue (older than the rotation
 * period plus two days). An overdue rotation keeps the status {@code UP},
 * because tokens are still signed; alert on the
 * {@code jacky917.as.signing_key.age} metric instead. No key material is
 * shown. The database connection is reported by Spring Boot's own data
 * source indicator.
 * <p>
 * 詳細資料包含金鑰 ID、演算法、使用天數，以及在啟用輪換時，輪換是否逾期（超過
 * 輪換週期加兩天）。輪換逾期時狀態仍為 {@code UP}，因為仍可簽發 token；請改以
 * {@code jacky917.as.signing_key.age} metric 告警。不包含任何金鑰內容。資料庫
 * 連線由 Spring Boot 本身的資料來源健康檢查回報。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SigningKeyHealthIndicator extends AbstractHealthIndicator {

    private static final Duration ROTATION_SLACK = Duration.ofDays(2);

    private final SigningKeyStore keys;
    private final Duration rotationPeriod;
    private final boolean rotationEnabled;
    private final Clock clock;

    /**
     * Creates the indicator.
     * <p>
     * 建立健康檢查。
     *
     * @param keys            the signing key store
     *                        <br>簽章金鑰儲存
     * @param rotationPeriod   the rotation period
     *                         <br>輪換週期
     * @param rotationEnabled  whether keys are rotated on a schedule; when
     *                         not, the key is never reported as overdue
     *                         <br>是否定期輪換金鑰；未啟用時不回報逾期
     * @param clock            the clock
     *                         <br>時鐘
     */
    public SigningKeyHealthIndicator(SigningKeyStore keys, Duration rotationPeriod, boolean rotationEnabled,
                                     Clock clock) {
        super("The signing key check failed");
        this.keys = keys;
        this.rotationPeriod = rotationPeriod;
        this.rotationEnabled = rotationEnabled;
        this.clock = clock;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        Optional<SigningKey> active = keys.findActive();
        if (active.isEmpty()) {
            builder.down().withDetail("reason", "There is no ACTIVE signing key");
            return;
        }
        double ageDays = AuthorizationServerMetrics.ageInDays(active.get(), clock.instant());
        builder.up()
                .withDetail("kid", active.get().kid())
                .withDetail("algorithm", active.get().algorithm())
                .withDetail("ageDays", Math.floor(ageDays * 10) / 10);
        if (rotationEnabled) {
            builder.withDetail("rotationOverdue",
                    ageDays > rotationPeriod.plus(ROTATION_SLACK).toMinutes() / (24.0 * 60));
        } else {
            builder.withDetail("rotationEnabled", false);
        }
    }
}
