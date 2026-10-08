package jacky917.security.authorizationserver.maintenance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.TaskScheduler;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link MaintenanceScheduler} 的單元測試：啟動後經過一個週期才第一次執行、取得鎖才執行、失敗不影響之後的執行。
 */
@DisplayName("MaintenanceScheduler")
class MaintenanceSchedulerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private TaskScheduler taskScheduler;
    private ScheduledJobLock lock;
    private final AtomicInteger runs = new AtomicInteger();
    private final MaintenanceScheduler.Job job =
            new MaintenanceScheduler.Job("cleanup", Duration.ofMinutes(10), runs::incrementAndGet);
    private MaintenanceScheduler scheduler;

    @BeforeEach
    void setUp() {
        taskScheduler = mock(TaskScheduler.class);
        lock = mock(ScheduledJobLock.class);
        scheduler = new MaintenanceScheduler(taskScheduler, lock, List.of(job), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("start：每個工作在一個週期之後第一次執行；stop 取消排程")
    void schedulesEveryJob() {
        ScheduledFuture<?> future = mock(ScheduledFuture.class);
        doReturn(future).when(taskScheduler).scheduleWithFixedDelay(any(Runnable.class), eq(NOW.plus(Duration.ofMinutes(10))),
                eq(Duration.ofMinutes(10)));
        scheduler.start();
        assertThat(scheduler.isRunning()).isTrue();
        scheduler.stop();
        verify(future).cancel(false);
        assertThat(scheduler.isRunning()).isFalse();
    }

    @Test
    @DisplayName("取得鎖（持有週期的 9 成時間）才執行；其他實例持有時略過")
    void runsOnlyWithTheLock() {
        when(lock.tryLock("jacky917-as.cleanup", Duration.ofMinutes(9))).thenReturn(true, false);
        scheduler.run(job);
        scheduler.run(job);
        assertThat(runs).hasValue(1);
    }

    @Test
    @DisplayName("工作失敗：記錄錯誤，不拋出（下一次照常執行）")
    void failuresAreLogged() {
        when(lock.tryLock(any(), any())).thenReturn(true);
        MaintenanceScheduler.Job failing = new MaintenanceScheduler.Job("failing", Duration.ofMinutes(10), () -> {
            throw new IllegalStateException("database is down");
        });
        assertThatCode(() -> scheduler.run(failing)).doesNotThrowAnyException();
    }
}
