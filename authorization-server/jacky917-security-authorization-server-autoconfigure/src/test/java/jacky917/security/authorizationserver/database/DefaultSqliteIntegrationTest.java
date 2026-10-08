package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 完全不設定 datasource 時，以預設 SQLite 啟動：建立資料庫檔案並執行 migration（詳細設計 T-DB-01）。
 * 以 {@code SpringApplication} 啟動，才會執行 {@code DefaultSqliteEnvironmentPostProcessor}。
 */
@DisplayName("預設 SQLite 整合測試")
class DefaultSqliteIntegrationTest {

    @TempDir
    Path dir;

    @Test
    @DisplayName("建立資料夾與資料庫檔案、執行 migration、使用 SQLite 方言")
    void startsWithDefaultSqlite() {
        Path database = dir.resolve("nested/auth.db");
        try (ConfigurableApplicationContext context = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database)) {
            assertThat(database).exists();
            assertThat(context.getBean(AuthorizationServerDialect.class)).isInstanceOf(SqliteDialect.class);
            assertThat(context.getEnvironment().getProperty("spring.datasource.url"))
                    .startsWith("jdbc:sqlite:" + database)
                    .endsWith(SqliteDialect.RECOMMENDED_URL_PARAMETERS);
            assertThat(context.getBean(JdbcClient.class).sql("SELECT COUNT(*) FROM app_role")
                    .query(Integer.class).single()).isEqualTo(3);
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    @DisplayName("新建立的資料庫檔案只有擁有者可讀寫（POSIX 600）")
    void databaseFileIsOwnerOnly() throws Exception {
        Path database = dir.resolve("auth.db");
        try (ConfigurableApplicationContext ignored = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database)) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(database))).isEqualTo("rw-------");
        }
    }

    @Test
    @DisplayName("應用程式設定的 spring.datasource.url 優先，不建立預設檔案")
    void applicationUrlWins() {
        Path database = dir.resolve("default.db");
        Path own = dir.resolve("own.db");
        try (ConfigurableApplicationContext context = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database,
                "--spring.datasource.url=jdbc:sqlite:" + own + "?" + SqliteDialect.RECOMMENDED_URL_PARAMETERS)) {
            assertThat(own).exists();
            assertThat(database).doesNotExist();
        }
    }

    @Test
    @DisplayName("應用程式自己的 Flyway migration（V1）照常執行；兩邊的歷史表分開，版本號不衝突")
    void applicationMigrationsRunAlongside() {
        Path database = dir.resolve("shared.db");
        try (ConfigurableApplicationContext context = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database,
                "--spring.flyway.locations=classpath:app-migrations")) {
            JdbcClient jdbc = context.getBean(JdbcClient.class);
            assertThat(jdbc.sql("SELECT COUNT(*) FROM app_note").query(Integer.class).single()).isZero();
            assertThat(jdbc.sql("SELECT version FROM flyway_schema_history WHERE success = 1 AND version = '1'")
                    .query(String.class).list()).as("應用程式的 V1 已執行，沒有被當成 baseline 略過").containsExactly("1");
            assertThat(jdbc.sql("SELECT version FROM jacky917_as_schema_history WHERE version LIKE '1.0.%'")
                    .query(String.class).list()).hasSize(7);
        }
        // 重新啟動：兩邊都沒有新的 migration，正常啟動
        try (ConfigurableApplicationContext ignored = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database,
                "--spring.flyway.locations=classpath:app-migrations")) {
            assertThat(ignored.isActive()).isTrue();
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    @DisplayName("預設的資料庫檔案已存在且權限較寬時，啟動時改為 600")
    void existingDatabaseFileIsRestricted() throws Exception {
        Path database = dir.resolve("loose.db");
        Files.createFile(database, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));
        try (ConfigurableApplicationContext ignored = start(
                "--jacky917.security.authorization-server.database.sqlite.path=" + database)) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(database))).isEqualTo("rw-------");
        }
    }

    private static ConfigurableApplicationContext start(String... args) {
        String[] all = new String[args.length + 2];
        System.arraycopy(args, 0, all, 0, args.length);
        all[args.length] = "--jacky917.security.authorization-server.issuer=http://localhost:9000";
        all[args.length + 1] = "--jacky917.security.authorization-server.keys.encryption-key="
                + TestDatabases.TEST_ENCRYPTION_KEY;
        return new SpringApplicationBuilder(TestApplication.class).web(WebApplicationType.NONE).run(all);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
    }
}
