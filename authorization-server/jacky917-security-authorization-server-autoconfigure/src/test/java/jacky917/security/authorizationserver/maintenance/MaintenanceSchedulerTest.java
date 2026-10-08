package jacky917.security.authorizationserver.maintenance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link MaintenanceScheduler} 的單元測試：啟動後經過一個週期才第一次執行、取得鎖才執行、失敗時發布事件並釋放鎖。
 */
@DisplayName("MaintenanceScheduler")
class MaintenanceSchedulerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private TaskScheduler taskScheduler;
    private ScheduledJobLock lock;
    private ApplicationEventPublisher events;
    private final AtomicInteger runs = new AtomicInteger();
    private final MaintenanceScheduler.Job job =
            new MaintenanceScheduler.Job("cleanup", Duration.ofMinutes(10), runs::incrementAndGet);
    private MaintenanceScheduler scheduler;

    @BeforeEach
    void setUp() {
        taskScheduler = mock(TaskScheduler.class);
        lock = mock(ScheduledJobLock.class);
        events = mock(ApplicationEventPublisher.class);
        scheduler = new MaintenanceScheduler(taskScheduler, lock, List.of(job), events,
                Clock.fixed(NOW, ZoneOffset.UTC));
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
    @DisplayName("工作失敗：不拋出，發布 MaintenanceFailedEvent，並釋放鎖讓任何實例下一次排程時重試")
    void failuresAreReportedAndReleaseTheLock() {
        when(lock.tryLock(any(), any())).thenReturn(true);
        MaintenanceScheduler.Job failing = new MaintenanceScheduler.Job("failing", Duration.ofMinutes(10), () -> {
            throw new IllegalStateException("database is down");
        });
        assertThatCode(() -> scheduler.run(failing)).doesNotThrowAnyException();
        verify(events).publishEvent(new MaintenanceFailedEvent("failing"));
        verify(lock).release("jacky917-as.failing");
    }

    @Test
    @DisplayName("取鎖本身失敗：發布失敗事件，但不釋放不屬於自己的鎖")
    void lockFailure() {
        when(lock.tryLock(any(), any())).thenThrow(new IllegalStateException("database is down"));
        assertThatCode(() -> scheduler.run(job)).doesNotThrowAnyException();
        verify(events).publishEvent(new MaintenanceFailedEvent("cleanup"));
        verify(lock, never()).release(any());
        assertThat(runs).hasValue(0);
    }

    @Test
    @DisplayName("成功的工作不提早釋放鎖")
    void successKeepsTheLock() {
        when(lock.tryLock(any(), any())).thenReturn(true);
        scheduler.run(job);
        verify(lock, never()).release(any());
        verify(events, never()).publishEvent(any(Object.class));
    }
}
