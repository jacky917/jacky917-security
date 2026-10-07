package jacky917.security.authorizationserver.database;

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

    private static ConfigurableApplicationContext start(String... args) {
        String[] all = new String[args.length + 1];
        System.arraycopy(args, 0, all, 0, args.length);
        all[args.length] = "--jacky917.security.authorization-server.issuer=http://localhost:9000";
        return new SpringApplicationBuilder(TestApplication.class).web(WebApplicationType.NONE).run(all);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
    }
}
