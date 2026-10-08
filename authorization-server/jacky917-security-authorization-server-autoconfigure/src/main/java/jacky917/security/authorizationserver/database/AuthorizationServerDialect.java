package jacky917.security.authorizationserver.database;

import javax.sql.DataSource;

/**
 * The few database behaviors that cannot be expressed in portable SQL.
 * <p>
 * 無法以可攜 SQL 表達的少數資料庫行為。
 * <p>
 * Repositories use the same SQL on every database; anything that differs
 * lives here. The migrations for each database are selected separately by
 * Flyway's {@code {vendor}} placeholder.
 * <p>
 * Repository 在所有資料庫上使用相同的 SQL，不同之處集中在這裡。各資料庫的
 * migration 則由 Flyway 的 {@code {vendor}} 佔位符另外選擇。
 *
 * @author Jacky
 * @since 2.1.0
 */
public interface AuthorizationServerDialect {

    /**
     * Returns the vendor id, which matches the migration folder name.
     * <p>
     * 回傳資料庫識別碼，與 migration 資料夾名稱相同。
     *
     * @return the vendor id, for example {@code postgresql} or {@code sqlite}
     *         <br>資料庫識別碼，例如 {@code postgresql}、{@code sqlite}
     */
    String vendor();

    /**
     * Returns the SQL that locks the authorization holding a refresh token
     * for the rest of the current transaction. It takes the token value as
     * its only parameter.
     * <p>
     * 回傳在目前交易結束前鎖定持有指定 Refresh Token 之授權的 SQL，唯一的
     * 參數為 token 值。
     *
     * @return the locking query
     *         <br>鎖定用的查詢
     */
    String lockAuthorizationByRefreshTokenSql();

    /**
     * Returns whether several application instances can share this
     * database.
     * <p>
     * 回傳多個應用程式實例能否共用此資料庫。
     *
     * @return {@code true} if multiple instances are supported
     *         <br>支援多實例時為 {@code true}
     */
    boolean supportsMultipleInstances();

    /**
     * Checks that the data source is configured as this dialect requires.
     * <p>
     * 檢查資料來源的設定是否符合此方言的要求。
     *
     * @param dataSource  the data source to check
     *                    <br>要檢查的資料來源
     * @throws IllegalStateException if a required setting is missing; the
     *         message lists what to change
     *         <br>缺少必要設定時拋出，訊息列出需要修改的地方
     */
    void validate(DataSource dataSource);
}
