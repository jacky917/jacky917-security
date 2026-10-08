package jacky917.security.authorizationserver.maintenance;

import java.util.Objects;

/**
 * Published when a scheduled job, or one cleanup step of it, fails, so the
 * failure can be counted and alerted on (detailed design §8.2).
 * <p>
 * 排程工作或其中一個清理步驟失敗時發布，以便計數與告警（詳細設計 §8.2）。
 *
 * @param task  the job name, for example {@code signing-key-rotation}, or
 *              {@code cleanup.} followed by the {@link CleanupTarget#tag()}
 *              of a cleanup step
 *              <br>工作名稱，例如 {@code signing-key-rotation}；或
 *              {@code cleanup.} 加上清理步驟的 {@code CleanupTarget#tag()}
 * @author Jacky
 * @since 2.1.0
 */
public record MaintenanceFailedEvent(String task) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     */
    public MaintenanceFailedEvent {
        Objects.requireNonNull(task, "task");
    }
}
