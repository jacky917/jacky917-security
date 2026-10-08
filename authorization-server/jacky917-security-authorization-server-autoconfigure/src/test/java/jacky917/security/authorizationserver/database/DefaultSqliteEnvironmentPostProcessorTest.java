package jacky917.security.authorizationserver.database;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DefaultSqliteEnvironmentPostProcessor} 的單元測試：預設值的優先序、停用時不動作、不提前建立檔案。
 */
@DisplayName("DefaultSqliteEnvironmentPostProcessor")
class DefaultSqliteEnvironmentPostProcessorTest {

    @TempDir
    Path dir;

    private final DefaultSqliteEnvironmentPostProcessor processor = new DefaultSqliteEnvironmentPostProcessor();

    @Test
    @DisplayName("沒有 datasource：預設 SQLite URL 與小連線池；只建立資料夾，不建立檔案")
    void defaultsToSqlite() throws Exception {
        Path database = dir.resolve("nested/auth.db");
        StandardEnvironment environment = environment(Map.of(
                "jacky917.security.authorization-server.database.sqlite.path", database.toString()));
        processor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getProperty("spring.datasource.url"))
                .isEqualTo("jdbc:sqlite:" + database + "?" + SqliteDialect.RECOMMENDED_URL_PARAMETERS);
        assertThat(environment.getProperty("spring.datasource.hikari.maximum-pool-size")).isEqualTo("4");
        assertThat(database.getParent()).isDirectory();
        assertThat(database).doesNotExist();
        if (!System.getProperty("os.name").startsWith("Windows")) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(database.getParent())))
                    .as("starter 建立的資料夾只有擁有者可進入").isEqualTo("rwx------");
        }
    }

    @Test
    @DisplayName("應用程式的設定優先：自訂 URL 不被覆蓋；Flyway 的 baseline 預設值也可被覆蓋")
    void applicationSettingsWin() {
        StandardEnvironment environment = environment(Map.of("spring.datasource.url", "jdbc:postgresql://db/auth",
                "spring.flyway.baseline-version", "5"));
        processor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getProperty("spring.datasource.url")).isEqualTo("jdbc:postgresql://db/auth");
        assertThat(environment.getProperty("spring.flyway.baseline-version")).isEqualTo("5");
        assertThat(environment.getProperty("spring.flyway.baseline-on-migrate")).isEqualTo("true");
        assertThat(environment.getProperty("spring.datasource.hikari.maximum-pool-size")).isNull();
    }

    @Test
    @DisplayName("停用 Authorization Server：不加入任何預設值")
    void disabled() {
        StandardEnvironment environment = environment(Map.of("jacky917.security.authorization-server.enabled", "false"));
        processor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getPropertySources().contains(DefaultSqliteEnvironmentPostProcessor.PROPERTY_SOURCE_NAME))
                .isFalse();
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    @DisplayName("restrictDefaultDatabaseFile：使用預設 URL 時主檔與 -wal、-shm 改為 600；URL 被其他設定取代時不動作")
    void restrictsOnlyTheDefaultFile() throws Exception {
        Path database = dir.resolve("auth.db");
        StandardEnvironment environment = environment(Map.of(
                "jacky917.security.authorization-server.database.sqlite.path", database.toString()));
        processor.postProcessEnvironment(environment, new SpringApplication());
        Files.createFile(database, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));

        environment.getPropertySources().addFirst(new MapPropertySource("test",
                Map.of("spring.datasource.url", "jdbc:sqlite:" + dir.resolve("other.db"))));
        DefaultSqliteEnvironmentPostProcessor.restrictDefaultDatabaseFile(environment);
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(database))).isEqualTo("rw-r--r--");

        environment.getPropertySources().remove("test");
        Path wal = Path.of(database + "-wal");
        Path shm = Path.of(database + "-shm");
        Files.createFile(wal, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));
        Files.createFile(shm, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));
        DefaultSqliteEnvironmentPostProcessor.restrictDefaultDatabaseFile(environment);
        for (Path file : new Path[]{database, wal, shm}) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(file))).as(file.toString())
                    .isEqualTo("rw-------");
        }
    }

    private static StandardEnvironment environment(Map<String, Object> properties) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("application", properties));
        return environment;
    }
}
