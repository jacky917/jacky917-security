package jacky917.security.authorizationserver.support;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import jacky917.security.authorizationserver.autoconfigure.AuthorizationServerAutoConfiguration;
import jacky917.security.authorizationserver.database.DefaultSqliteEnvironmentPostProcessor;
import jacky917.security.authorizationserver.database.SqliteDialect;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.JdbcClientAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.transaction.autoconfigure.TransactionAutoConfiguration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 測試用資料庫：SQLite 暫存檔，以及整個 JVM 共用一個 embedded PostgreSQL 16（不需要 Docker），
 * 每次取得網址時建立一個新的資料庫，測試之間互不影響。
 */
public final class TestDatabases {

    /**
     * 兩種資料庫的名稱，供參數化測試使用。
     */
    public static final String SQLITE = "sqlite";
    public static final String POSTGRESQL = "postgresql";

    /**
     * 測試用主金鑰（32 bytes 的 Base64），只用於測試。
     */
    public static final String TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    private static final AtomicInteger COUNTER = new AtomicInteger();
    private static EmbeddedPostgres postgres;

    private TestDatabases() {
    }

    /**
     * 回傳新的空白資料庫的 JDBC URL。
     */
    public static String newDatabaseUrl(String vendor) {
        return switch (vendor) {
            case SQLITE -> newSqliteUrl();
            case POSTGRESQL -> newPostgresUrl();
            default -> throw new IllegalArgumentException(vendor);
        };
    }

    /**
     * 只執行資料庫相關自動配置的 runner；migration 位置與 issuer 已設定。
     * <p>
     * {@code ApplicationContextRunner} 不會執行 {@code EnvironmentPostProcessor}，所以由這裡補上 Flyway 位置。
     */
    public static ApplicationContextRunner runner(String vendor) {
        return runner(vendor, newDatabaseUrl(vendor));
    }

    /**
     * 使用指定資料庫的 runner，可用來模擬同一個資料庫上的重新啟動。
     */
    public static ApplicationContextRunner runner(String vendor, String url) {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        DataSourceAutoConfiguration.class,
                        DataSourceTransactionManagerAutoConfiguration.class,
                        JdbcTemplateAutoConfiguration.class,
                        JdbcClientAutoConfiguration.class,
                        TransactionAutoConfiguration.class,
                        FlywayAutoConfiguration.class,
                        AuthorizationServerAutoConfiguration.class))
                .withPropertyValues(
                        "spring.datasource.url=" + url,
                        "spring.flyway.locations=" + DefaultSqliteEnvironmentPostProcessor.MIGRATION_LOCATION,
                        "jacky917.security.authorization-server.issuer=http://localhost:9000",
                        "jacky917.security.authorization-server.keys.encryption-key=" + TEST_ENCRYPTION_KEY);
        if (POSTGRESQL.equals(vendor)) {
            runner = runner.withPropertyValues("spring.datasource.username=postgres");
        }
        return runner;
    }

    private static String newSqliteUrl() {
        try {
            Path dir = Files.createTempDirectory("jacky917-as-test");
            return "jdbc:sqlite:" + dir.resolve("auth.db") + "?" + SqliteDialect.RECOMMENDED_URL_PARAMETERS;
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static synchronized String newPostgresUrl() {
        try {
            if (postgres == null) {
                postgres = EmbeddedPostgres.builder().start();
                EmbeddedPostgres started = postgres;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    try {
                        started.close();
                    } catch (IOException ignored) {
                        // JVM 結束中，忽略
                    }
                }));
            }
            String database = "as_test_" + COUNTER.incrementAndGet();
            try (Connection connection = postgres.getPostgresDatabase().getConnection();
                 Statement statement = connection.createStatement()) {
                statement.execute("CREATE DATABASE " + database);
            }
            return postgres.getJdbcUrl("postgres", database);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (SQLException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
