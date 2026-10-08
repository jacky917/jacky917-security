package jacky917.security.authorizationserver.maintenance;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.SmartLifecycle;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

/**
 * Runs the authorization server's scheduled jobs: key rotation and
 * cleanup (detailed design §5.7, §5.8).
 * <p>
 * 執行 Authorization Server 的排程工作：金鑰輪換與清理（詳細設計 §5.7、§5.8）。
 * <p>
 * Each job first runs one period after startup, then every period, so that
 * restarting several instances does not run every job at once. An
 * application that restarts more often than a job's period, for example one
 * deployed every day, never reaches the daily cleanup; run
 * {@link DataCleanup#runAll()} from an administration task instead. Across
 * several instances, {@link ScheduledJobLock} lets only one of them run a job
 * in each 90% of its period; the other 10% keeps this instance's own next
 * run from being blocked by its lock. A failing job is logged, reported with
 * a {@link MaintenanceFailedEvent} and releases its lock, so it runs again at
 * the next time of any instance. The jobs use their own thread and never
 * turn on {@code @Scheduled} in the application.
 * <p>
 * 每個工作在啟動後經過一個週期才第一次執行，之後每個週期執行一次，避免同時
 * 重啟多個實例時所有工作一起執行。重啟頻率高於工作週期的應用程式（例如每天
 * 部署）永遠等不到每日清理，請改由管理工作呼叫 {@code DataCleanup#runAll()}。
 * 多個實例時，{@code ScheduledJobLock} 讓每段「週期的 90%」只有一個實例執行；
 * 保留 10% 是為了不讓本實例的下一次執行被自己的鎖擋住。失敗的工作記錄日誌、以
 * {@code MaintenanceFailedEvent} 回報並釋放鎖，因此任何實例的下一次排程都會
 * 重試。工作使用自己的執行緒，不會啟用應用程式的 {@code @Scheduled}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class MaintenanceScheduler implements SmartLifecycle {

    private final TaskScheduler scheduler;
    private final ScheduledJobLock lock;
    private final List<Job> jobs;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final List<ScheduledFuture<?>> scheduled = new ArrayList<>();
    private volatile boolean running;

    /**
     * Creates the scheduler.
     * <p>
     * 建立排程器。
     *
     * @param scheduler  runs the jobs; a {@link ThreadPoolTaskScheduler} is
     *                   shut down when this scheduler stops
     *                   <br>執行工作；若為 {@code ThreadPoolTaskScheduler}，
     *                   在此排程器停止時關閉
     * @param lock       lets one instance run each job per period
     *                   <br>讓每個週期只有一個實例執行工作
     * @param jobs       the jobs
     *                   <br>工作
     * @param events     publishes a {@link MaintenanceFailedEvent} when a
     *                   job fails
     *                   <br>工作失敗時發布 {@code MaintenanceFailedEvent}
     * @param clock      the clock
     *                   <br>時鐘
     */
    public MaintenanceScheduler(TaskScheduler scheduler, ScheduledJobLock lock, List<Job> jobs,
                                ApplicationEventPublisher events, Clock clock) {
        this.scheduler = scheduler;
        this.lock = lock;
        this.jobs = List.copyOf(jobs);
        this.events = events;
        this.clock = clock;
    }

    /**
     * Creates a task scheduler with one daemon thread for the jobs.
     * <p>
     * 為工作建立只有一個 daemon 執行緒的 task scheduler。
     *
     * @return the initialized task scheduler
     *         <br>已初始化的 task scheduler
     */
    public static ThreadPoolTaskScheduler newTaskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(1);
        scheduler.setDaemon(true);
        scheduler.setThreadNamePrefix("jacky917-as-maintenance-");
        scheduler.initialize();
        return scheduler;
    }

    @Override
    public synchronized void start() {
        for (Job job : jobs) {
            scheduled.add(scheduler.scheduleWithFixedDelay(() -> run(job), clock.instant().plus(job.period()),
                    job.period()));
        }
        running = true;
    }

    @Override
    public synchronized void stop() {
        scheduled.forEach(future -> future.cancel(false));
        scheduled.clear();
        if (scheduler instanceof ThreadPoolTaskScheduler pool) {
            pool.shutdown();
        }
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    /**
     * Runs one job now if this instance gets its lock.
     * <p>
     * 若本實例取得鎖，立即執行一個工作。
     *
     * @param job  the job
     *             <br>工作
     */
    void run(Job job) {
        String lockName = "jacky917-as." + job.name();
        boolean locked = false;
        try {
            // 持有鎖到本實例下一次排程之前；排程時間不同的其他實例在這段時間內不會執行
            locked = lock.tryLock(lockName, job.period().multipliedBy(9).dividedBy(10));
            if (!locked) {
                log.debug("Skipping scheduled job {}: another instance ran it recently", job.name());
                return;
            }
            job.task().run();
        } catch (RuntimeException ex) {
            log.error("Scheduled job {} failed; any instance retries it at its next run, at most {} from now",
                    job.name(), job.period(), ex);
            events.publishEvent(new MaintenanceFailedEvent(job.name()));
            if (locked) {
                releaseAfterFailure(lockName);
            }
        }
    }

    private void releaseAfterFailure(String lockName) {
        try {
            lock.release(lockName);
        } catch (RuntimeException ex) {
            log.warn("Cannot release the lock {} after a failure; it expires on its own", lockName, ex);
        }
    }

    /**
     * A job run every period.
     * <p>
     * 每個週期執行一次的工作。
     *
     * @param name    the job name, also the lock name
     *                <br>工作名稱，也是鎖的名稱
     * @param period  the time between runs
     *                <br>兩次執行之間的時間
     * @param task    the work
     *                <br>工作內容
     */
    public record Job(String name, Duration period, Runnable task) {
    }
}
