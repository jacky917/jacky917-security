package jacky917.security.authorizationserver.maintenance;

import java.util.Objects;

/**
 * Published after a cleanup deleted or changed rows. For
 * {@link CleanupTarget#EXPIRED_SESSIONS} the rows were marked
 * {@code EXPIRED}; for {@link CleanupTarget#AUDITS} the count covers both
 * audit tables.
 * <p>
 * 清理刪除或變更資料之後發布。{@code EXPIRED_SESSIONS} 的資料是改為
 * {@code EXPIRED}；{@code AUDITS} 的筆數為兩張稽核表的合計。
 *
 * @param target  what was cleaned
 *                <br>清理的對象
 * @param count   the number of rows; greater than zero
 *                <br>筆數，大於零
 * @author Jacky
 * @since 2.1.0
 */
public record DataCleanupEvent(CleanupTarget target, int count) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     *
     * @throws IllegalArgumentException if {@code count} is not positive
     *         <br>若 {@code count} 不是正數
     */
    public DataCleanupEvent {
        Objects.requireNonNull(target, "target");
        if (count <= 0) {
            throw new IllegalArgumentException("A cleanup event needs a positive count: " + count);
        }
    }
}
