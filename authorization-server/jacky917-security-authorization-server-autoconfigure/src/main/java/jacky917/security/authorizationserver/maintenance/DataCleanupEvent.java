package jacky917.security.authorizationserver.maintenance;

/**
 * Published after a scheduled cleanup deleted or changed rows.
 * <p>
 * 排程清理刪除或變更資料之後發布。
 *
 * @param target  what was cleaned, for example {@code authorizations}
 *                <br>清理的對象，例如 {@code authorizations}
 * @param count   the number of rows; greater than zero
 *                <br>筆數，大於零
 * @author Jacky
 * @since 2.1.0
 */
public record DataCleanupEvent(String target, int count) {
}
