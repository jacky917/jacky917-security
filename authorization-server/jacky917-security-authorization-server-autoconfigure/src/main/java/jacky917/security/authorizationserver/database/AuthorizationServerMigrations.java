package jacky917.security.authorizationserver.database;

import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.InitializingBean;

import javax.sql.DataSource;

/**
 * Runs the authorization server's own migrations with a dedicated Flyway
 * instance and history table, separate from the application's Flyway.
 * <p>
 * 以專屬的 Flyway 實例與歷史表執行 Authorization Server 自己的 migration，與
 * 應用程式的 Flyway 分開。
 * <p>
 * The application keeps Spring Boot's Flyway for its own tables
 * ({@code db/migration}, {@code flyway_schema_history}); the two sets of
 * versions never collide. Because both share one database, each baselines
 * at version 0 when it finds the other's tables, so all of its own
 * migrations still run.
 * <p>
 * 應用程式仍以 Spring Boot 的 Flyway 管理自己的表（{@code db/migration}、
 * {@code flyway_schema_history}），兩邊的版本號不會衝突。由於兩者共用同一個
 * 資料庫，任一方發現另一方的表時都會以版本 0 建立 baseline，自己的 migration
 * 仍會全部執行。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AuthorizationServerMigrations implements InitializingBean {

    /**
     * History table of the authorization server migrations.
     * <p>
     * Authorization Server migration 的歷史表。
     */
    public static final String HISTORY_TABLE = "jacky917_as_schema_history";

    /**
     * Location of the migrations; the vendor folder is appended.
     * <p>
     * Migration 的位置，後面接上資料庫資料夾名稱。
     */
    public static final String LOCATION_PREFIX = "classpath:db/jacky917-as/";

    private final DataSource dataSource;
    private final AuthorizationServerDialect dialect;

    /**
     * Creates the runner.
     * <p>
     * 建立執行器。
     *
     * @param dataSource  the authorization server's data source
     *                    <br>Authorization Server 的資料來源
     * @param dialect     selects the migration folder
     *                    <br>決定使用的 migration 資料夾
     */
    public AuthorizationServerMigrations(DataSource dataSource, AuthorizationServerDialect dialect) {
        this.dataSource = dataSource;
        this.dialect = dialect;
    }

    @Override
    public void afterPropertiesSet() {
        Flyway.configure()
                .dataSource(dataSource)
                .locations(LOCATION_PREFIX + dialect.vendor())
                .table(HISTORY_TABLE)
                .baselineOnMigrate(true)
                .baselineVersion("0")
                .cleanDisabled(true)
                .load()
                .migrate();
    }
}
