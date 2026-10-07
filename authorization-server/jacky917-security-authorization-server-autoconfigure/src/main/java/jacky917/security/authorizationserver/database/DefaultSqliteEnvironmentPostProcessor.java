package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Adds the authorization server's database defaults with the lowest
 * precedence, so any value the application sets wins.
 * <p>
 * 以最低優先序加入 Authorization Server 的資料庫預設值，應用程式自行設定的值
 * 一律優先。
 * <ul>
 *   <li>When {@code spring.datasource.url} is not set, the application uses
 *       a SQLite file with the required connection parameters, and its
 *       parent directory is created.
 *       <br>未設定 {@code spring.datasource.url} 時，使用帶有必要連線參數的
 *       SQLite 檔案，並建立其上層資料夾。</li>
 *   <li>The application's own Flyway (Spring Boot's) baselines at version 0
 *       when it finds the authorization server's tables, so all of the
 *       application's migrations still run. The authorization server's
 *       migrations use their own Flyway instance and history table
 *       ({@link AuthorizationServerMigrations}).
 *       <br>應用程式自己的 Flyway（Spring Boot 的）發現 Authorization Server
 *       的表時以版本 0 建立 baseline，應用程式的 migration 仍會全部執行。
 *       Authorization Server 的 migration 使用自己的 Flyway 實例與歷史表
 *       （{@link AuthorizationServerMigrations}）。</li>
 * </ul>
 * The database file is not created here: a later property source (for
 * example a test) may still replace the URL. Its permissions are restricted
 * before any secret is written, by {@link #restrictDefaultDatabaseFile}.
 * <p>
 * 這裡不建立資料庫檔案：之後的 property source（例如測試）仍可能取代 URL。
 * 檔案權限由 {@link #restrictDefaultDatabaseFile} 在寫入任何機密資料前限制。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class DefaultSqliteEnvironmentPostProcessor implements EnvironmentPostProcessor {

    /**
     * Name of the property source that holds the defaults.
     * <p>
     * 存放預設值的 property source 名稱。
     */
    public static final String PROPERTY_SOURCE_NAME = "jacky917AuthorizationServerDatabaseDefaults";

    private static final String DEFAULT_PATH = "./data/jacky917-auth.db";
    private static final String DATASOURCE_URL = "spring.datasource.url";
    private static final String DEFAULT_FILE = "jacky917.internal.authorization-server.default-sqlite-file";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (!environment.getProperty(AuthorizationServerProperties.PREFIX + ".enabled", Boolean.class, true)) {
            return;
        }
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("spring.flyway.baseline-on-migrate", true);
        defaults.put("spring.flyway.baseline-version", "0");
        if (!StringUtils.hasText(environment.getProperty(DATASOURCE_URL))) {
            Path path = Path.of(environment.getProperty(
                    AuthorizationServerProperties.PREFIX + ".database.sqlite.path", DEFAULT_PATH));
            createParentDirectory(path);
            defaults.put(DATASOURCE_URL, "jdbc:sqlite:" + path + "?" + SqliteDialect.RECOMMENDED_URL_PARAMETERS);
            defaults.put(DEFAULT_FILE, path.toString());
            // 寫入依序執行，連線再多也只是排隊；維持較小的連線池
            defaults.put("spring.datasource.hikari.maximum-pool-size", 4);
        }
        environment.getPropertySources().addLast(new MapPropertySource(PROPERTY_SOURCE_NAME, defaults));
    }

    /**
     * Restricts the default SQLite file to its owner (POSIX {@code 600})
     * when the application still uses the default URL, because the file
     * holds tokens and encrypted keys. Does nothing otherwise.
     * <p>
     * 應用程式仍使用預設 URL 時，把預設的 SQLite 檔案限制為只有擁有者可讀寫
     * （POSIX {@code 600}），因為其中存放 token 與加密後的金鑰；其他情況不做
     * 任何事。
     *
     * @param environment  the application environment
     *                     <br>應用程式的環境
     */
    public static void restrictDefaultDatabaseFile(Environment environment) {
        if (!(environment instanceof ConfigurableEnvironment configurable)) {
            return;
        }
        PropertySource<?> defaults = configurable.getPropertySources().get(PROPERTY_SOURCE_NAME);
        if (defaults == null || defaults.getProperty(DEFAULT_FILE) == null
                || !Objects.equals(defaults.getProperty(DATASOURCE_URL), environment.getProperty(DATASOURCE_URL))) {
            return;
        }
        Path path = Path.of((String) defaults.getProperty(DEFAULT_FILE));
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        try {
            if (Files.notExists(path)) {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } else {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("Cannot restrict the permissions of " + path.toAbsolutePath(), ex);
        }
    }

    private static void createParentDirectory(Path path) {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("Cannot create the directory of " + path.toAbsolutePath(), ex);
        }
    }
}
