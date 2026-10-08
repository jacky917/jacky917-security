package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties.DialectType;
import org.springframework.boot.jdbc.DatabaseDriver;
import org.springframework.jdbc.support.JdbcUtils;

import javax.sql.DataSource;
import java.sql.DatabaseMetaData;

/**
 * Chooses the {@link AuthorizationServerDialect} for a data source.
 * <p>
 * 為資料來源選擇 {@link AuthorizationServerDialect}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class AuthorizationServerDialects {

    private AuthorizationServerDialects() {
    }

    /**
     * Returns the dialect for the configured type, detecting it from the
     * JDBC URL when the type is {@link DialectType#AUTO}.
     * <p>
     * 依設定的類型回傳方言；類型為 {@link DialectType#AUTO} 時依 JDBC URL 判斷。
     *
     * @param type        the configured dialect type
     *                    <br>設定的方言類型
     * @param dataSource  the data source used to detect the database
     *                    <br>用來判斷資料庫的資料來源
     * @return the matching dialect
     *         <br>對應的方言
     * @throws IllegalStateException if the database is not supported
     *         <br>資料庫不受支援時
     */
    public static AuthorizationServerDialect select(DialectType type, DataSource dataSource) {
        return switch (type) {
            case POSTGRESQL -> new PostgresqlDialect();
            case SQLITE -> new SqliteDialect();
            case AUTO -> detect(dataSource);
        };
    }

    private static AuthorizationServerDialect detect(DataSource dataSource) {
        String url;
        try {
            url = JdbcUtils.extractDatabaseMetaData(dataSource, DatabaseMetaData::getURL);
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot detect the database of the authorization server", ex);
        }
        DatabaseDriver driver = DatabaseDriver.fromJdbcUrl(url);
        return switch (driver) {
            case POSTGRESQL -> new PostgresqlDialect();
            case SQLITE -> new SqliteDialect();
            default -> throw new IllegalStateException("The authorization server supports SQLite and PostgreSQL, but the "
                    + "data source is " + driver.getId() + ". Set spring.datasource.url to a supported database.");
        };
    }
}
