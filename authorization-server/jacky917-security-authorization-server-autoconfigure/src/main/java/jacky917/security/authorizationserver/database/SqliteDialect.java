package jacky917.security.authorizationserver.database;

import com.zaxxer.hikari.HikariDataSource;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Dialect for SQLite, the default database.
 * <p>
 * SQLite 的方言，也是預設資料庫。
 * <p>
 * SQLite needs connection parameters that are off by default: without
 * {@code foreign_keys=true} cascading deletes silently do nothing, and
 * without {@code transaction_mode=IMMEDIATE} concurrent refreshes are not
 * serialized. {@link #validate(DataSource)} therefore fails startup when
 * any of them is missing. SQLite supports a single application instance
 * only.
 * <p>
 * SQLite 需要幾個預設關閉的連線參數：沒有 {@code foreign_keys=true} 時，連帶
 * 刪除會靜默失效；沒有 {@code transaction_mode=IMMEDIATE} 時，併發的刷新不會
 * 依序執行。因此 {@link #validate(DataSource)} 在缺少任何一項時讓啟動失敗。
 * SQLite 只支援單一應用程式實例。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SqliteDialect implements AuthorizationServerDialect {

    /**
     * Connection parameters that every SQLite URL must contain, with their
     * required values.
     * <p>
     * 每個 SQLite URL 都必須包含的連線參數與其值。
     */
    public static final Map<String, String> REQUIRED_URL_PARAMETERS = requiredParameters();

    /**
     * Recommended connection parameters: the required ones plus a busy
     * timeout so that a writer waits instead of failing immediately.
     * <p>
     * 建議的連線參數：必要參數加上 busy timeout，讓寫入時等待而不是立即失敗。
     */
    public static final String RECOMMENDED_URL_PARAMETERS =
            "foreign_keys=true&journal_mode=WAL&busy_timeout=5000&transaction_mode=IMMEDIATE&date_class=INTEGER";

    private static Map<String, String> requiredParameters() {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("foreign_keys", "true");
        parameters.put("journal_mode", "WAL");
        parameters.put("transaction_mode", "IMMEDIATE");
        parameters.put("date_class", "INTEGER");
        return Map.copyOf(parameters);
    }

    @Override
    public String vendor() {
        return "sqlite";
    }

    @Override
    public String lockAuthorizationSql() {
        // SQLite 沒有 FOR UPDATE：transaction_mode=IMMEDIATE 讓交易開始時就取得資料庫寫入鎖，效果相同
        return "SELECT id FROM oauth2_authorization WHERE id = ?";
    }

    @Override
    public boolean supportsMultipleInstances() {
        return false;
    }

    @Override
    public void validate(DataSource dataSource) {
        List<String> problems = new ArrayList<>();
        String url = jdbcUrl(dataSource, problems);
        if (url != null) {
            Map<String, String> parameters = parseParameters(url);
            REQUIRED_URL_PARAMETERS.forEach((name, expected) -> {
                String actual = parameters.get(name);
                if (actual == null || !actual.equalsIgnoreCase(expected)) {
                    problems.add("URL parameter " + name + "=" + expected + " is missing");
                }
            });
        }
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            if (!"1".equals(pragma(statement, "foreign_keys"))) {
                problems.add("PRAGMA foreign_keys is not enabled");
            }
            if (!"wal".equalsIgnoreCase(pragma(statement, "journal_mode"))) {
                problems.add("PRAGMA journal_mode is not WAL");
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Cannot check the SQLite connection settings", ex);
        }
        if (!problems.isEmpty()) {
            throw new IllegalStateException("SQLite is not configured as the authorization server requires: "
                    + String.join("; ", problems) + ". Use a URL such as jdbc:sqlite:./data/jacky917-auth.db?"
                    + RECOMMENDED_URL_PARAMETERS + " with HikariCP and spring.datasource.hikari.auto-commit=true.");
        }
    }

    private static String jdbcUrl(DataSource dataSource, List<String> problems) {
        try {
            if (dataSource.isWrapperFor(HikariDataSource.class)) {
                HikariDataSource hikari = dataSource.unwrap(HikariDataSource.class);
                // xerial 在 IMMEDIATE 模式下 commit 後會立刻開始新交易並持有寫入鎖；只有自動提交才會釋放
                if (!hikari.isAutoCommit()) {
                    problems.add("spring.datasource.hikari.auto-commit must be true");
                }
                return hikari.getJdbcUrl();
            }
            if (dataSource.isWrapperFor(SQLiteDataSource.class)) {
                // SQLiteDataSource 不會套用 URL 中的 transaction_mode，交易不會依序執行
                problems.add("SQLiteDataSource ignores transaction_mode; use HikariCP (the Spring Boot default)");
                return null;
            }
            try (Connection connection = dataSource.getConnection()) {
                return connection.getMetaData().getURL();
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Cannot read the SQLite JDBC URL", ex);
        }
    }

    static Map<String, String> parseParameters(String url) {
        Map<String, String> parameters = new LinkedHashMap<>();
        int start = url.indexOf('?');
        if (start < 0) {
            return parameters;
        }
        for (String pair : url.substring(start + 1).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                parameters.put(pair.substring(0, equals).trim().toLowerCase(Locale.ROOT), pair.substring(equals + 1).trim());
            }
        }
        return parameters;
    }

    private static String pragma(Statement statement, String name) throws SQLException {
        try (ResultSet resultSet = statement.executeQuery("PRAGMA " + name)) {
            return resultSet.next() ? resultSet.getString(1) : null;
        }
    }
}
