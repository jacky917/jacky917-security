package jacky917.security.authorizationserver.maintenance;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.lang.management.ManagementFactory;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Makes a scheduled job run on one application instance per period, using
 * the {@code shedlock} table (data model §8.4).
 * <p>
 * 讓排程工作在每個週期只於一個應用程式實例上執行，使用 {@code shedlock} 表
 * （資料模型 §8.4）。
 * <p>
 * The first instance to call {@link #tryLock} holds the lock for the given
 * time and runs the job; the others skip it. A successful job never
 * releases the lock early, so it runs at most once per hold time even when
 * the instances' schedules are not aligned. A failed job releases it with
 * {@link #release}, so any instance can retry at its next run instead of
 * waiting for the hold time. A crashed instance loses the lock when the hold
 * time ends.
 * <p>
 * 第一個呼叫 {@code tryLock} 的實例在指定時間內持有鎖並執行工作，其他實例略過。
 * 成功的工作不會提早釋放鎖，因此即使各實例的排程時間不一致，每段持有時間內最多
 * 只執行一次。失敗的工作以 {@code release} 釋放鎖，任何實例都能在下一次排程時
 * 重試，而不必等到持有時間結束。實例當機時，鎖在持有時間結束後自動失效。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ScheduledJobLock {

    private final JdbcClient jdbc;
    private final Clock clock;
    private final String owner = ManagementFactory.getRuntimeMXBean().getName();

    /**
     * Creates the lock.
     * <p>
     * 建立鎖。
     *
     * @param jdbc   the JDBC client of the authorization server database
     *               <br>Authorization Server 資料庫的 JDBC client
     * @param clock  the clock
     *               <br>時鐘
     */
    public ScheduledJobLock(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /**
     * Takes the lock of a job if no instance holds it.
     * <p>
     * 若沒有任何實例持有，取得工作的鎖。
     *
     * @param name     the job name, at most 64 characters
     *                 <br>工作名稱，最多 64 字元
     * @param holdFor  how long the lock is held
     *                 <br>持有鎖的時間
     * @return {@code true} if this instance now holds the lock and should
     *         run the job
     *         <br>本實例取得鎖、應執行工作時為 {@code true}
     */
    public boolean tryLock(String name, Duration holdFor) {
        Instant now = clock.instant();
        Timestamp until = Timestamp.from(now.plus(holdFor));
        int updated = jdbc.sql("UPDATE shedlock SET lock_until = :until, locked_at = :now, locked_by = :owner "
                        + "WHERE name = :name AND lock_until <= :now")
                .param("until", until).param("now", Timestamp.from(now)).param("owner", owner).param("name", name)
                .update();
        if (updated == 1) {
            return true;
        }
        try {
            jdbc.sql("INSERT INTO shedlock (name, lock_until, locked_at, locked_by) VALUES (:name, :until, :now, :owner)")
                    .param("name", name).param("until", until).param("now", Timestamp.from(now)).param("owner", owner)
                    .update();
            return true;
        } catch (DuplicateKeyException ex) {
            // 另一個實例持有鎖（或同時取得了它）
            return false;
        }
    }

    /**
     * Releases a lock this instance holds, for example after the job
     * failed. A lock held by another instance is left alone.
     * <p>
     * 釋放本實例持有的鎖，例如在工作失敗之後。其他實例持有的鎖不受影響。
     *
     * @param name  the job name
     *              <br>工作名稱
     */
    public void release(String name) {
        Timestamp now = Timestamp.from(clock.instant());
        jdbc.sql("UPDATE shedlock SET lock_until = :now WHERE name = :name AND locked_by = :owner AND lock_until > :now")
                .param("now", now).param("name", name).param("owner", owner).update();
    }
}
