package jacky917.security.authorizationserver.maintenance;

import lombok.extern.slf4j.Slf4j;
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
 * Each job first runs one period after startup, then every period. Across
 * several instances, {@link ScheduledJobLock} lets only one of them run a job
 * per period. A failing job is logged and runs again at its next time. The
 * jobs use their own thread and never turn on {@code @Scheduled} in the
 * application.
 * <p>
 * 每個工作在啟動後經過一個週期才第一次執行，之後每個週期執行一次。多個實例時，
 * {@code ScheduledJobLock} 讓每個週期只有一個實例執行。失敗的工作記錄日誌，
 * 下一次照常執行。工作使用自己的執行緒，不會啟用應用程式的 {@code @Scheduled}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class MaintenanceScheduler implements SmartLifecycle {

    private final TaskScheduler scheduler;
    private final ScheduledJobLock lock;
    private final List<Job> jobs;
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
     * @param clock      the clock
     *                   <br>時鐘
     */
    public MaintenanceScheduler(TaskScheduler scheduler, ScheduledJobLock lock, List<Job> jobs, Clock clock) {
        this.scheduler = scheduler;
        this.lock = lock;
        this.jobs = List.copyOf(jobs);
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
        try {
            // 持有鎖到下一次排程之前：其他實例在這個週期內不會再執行
            if (lock.tryLock("jacky917-as." + job.name(), job.period().multipliedBy(9).dividedBy(10))) {
                job.task().run();
            }
        } catch (RuntimeException ex) {
            log.error("Scheduled job {} failed; it runs again in {}", job.name(), job.period(), ex);
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
