package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.database.AuthorizationServerDialect;
import jacky917.security.authorizationserver.database.AuthorizationServerDialects;
import jacky917.security.authorizationserver.database.AuthorizationServerMigrations;
import jacky917.security.authorizationserver.database.DefaultSqliteEnvironmentPostProcessor;
import jacky917.security.authorizationserver.database.SqliteExceptionTranslatorPostProcessor;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

/**
 * Database configuration (D22): chooses the dialect and checks the
 * connection settings at startup.
 * <p>
 * 資料庫配置（D22）：選擇方言，並在啟動時檢查連線設定。
 * <p>
 * The default SQLite URL is added earlier by
 * {@link DefaultSqliteEnvironmentPostProcessor}.
 * <p>
 * 預設的 SQLite URL 由 {@code DefaultSqliteEnvironmentPostProcessor} 預先加入。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerDatabaseConfiguration {

    /**
     * Creates the dialect for the configured or detected database and
     * validates the data source with it, so a misconfigured database fails
     * startup.
     * <p>
     * 為設定或偵測到的資料庫建立方言，並以它檢查資料來源，讓設定錯誤的資料庫
     * 在啟動時就失敗。
     *
     * @param dataSource  the authorization server's data source
     *                    <br>Authorization Server 的資料來源
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 的設定屬性
     * @return the validated dialect
     *         <br>已通過檢查的方言
     */
    @Bean
    @ConditionalOnMissingBean
    AuthorizationServerDialect authorizationServerDialect(DataSource dataSource,
                                                          AuthorizationServerProperties properties) {
        AuthorizationServerDialect dialect =
                AuthorizationServerDialects.select(properties.getDatabase().getDialect(), dataSource);
        dialect.validate(dataSource);
        return dialect;
    }

    /**
     * Runs the authorization server's migrations with their own Flyway
     * instance and history table. The default SQLite file is restricted to
     * its owner first, before any secret is written.
     * <p>
     * 以專屬的 Flyway 實例與歷史表執行 Authorization Server 的 migration。執行前
     * 先把預設的 SQLite 檔案限制為只有擁有者可讀寫，再寫入任何機密資料。
     *
     * @param dataSource   the authorization server's data source
     *                     <br>Authorization Server 的資料來源
     * @param dialect      the validated dialect
     *                     <br>已通過檢查的方言
     * @param environment  the application environment
     *                     <br>應用程式的環境
     * @return the migration runner
     *         <br>migration 執行器
     */
    @Bean
    AuthorizationServerMigrations authorizationServerMigrations(DataSource dataSource,
                                                                AuthorizationServerDialect dialect,
                                                                Environment environment) {
        DefaultSqliteEnvironmentPostProcessor.restrictDefaultDatabaseFile(environment);
        return new AuthorizationServerMigrations(dataSource, dialect);
    }

    /**
     * Makes {@code JdbcTemplate} report SQLite constraint violations as
     * Spring's {@code DataIntegrityViolationException} family, as it does
     * for PostgreSQL.
     * <p>
     * 讓 {@code JdbcTemplate} 把 SQLite 的約束違反轉為 Spring 的
     * {@code DataIntegrityViolationException} 系列，與 PostgreSQL 一致。
     *
     * @return the post-processor
     *         <br>bean post-processor
     */
    @Bean
    static SqliteExceptionTranslatorPostProcessor sqliteExceptionTranslatorPostProcessor() {
        return new SqliteExceptionTranslatorPostProcessor();
    }
}
