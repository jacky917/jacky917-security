package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Adds the authorization server's database defaults with the lowest
 * precedence, so any value the application sets wins.
 * <p>
 * 以最低優先序加入 Authorization Server 的資料庫預設值，應用程式自行設定的值
 * 一律優先。
 * <ul>
 *   <li>{@code spring.flyway.locations} points at the migrations shipped
 *       with the starter, chosen per database by {@code {vendor}}.
 *       <br>{@code spring.flyway.locations} 指向 starter 隨附的 migration，
 *       由 {@code {vendor}} 依資料庫選擇。</li>
 *   <li>When {@code spring.datasource.url} is not set, the application uses
 *       a SQLite file with the required connection parameters. The parent
 *       directory is created, and a new file is readable only by the
 *       owner on POSIX systems, because it holds tokens and encrypted
 *       keys.
 *       <br>未設定 {@code spring.datasource.url} 時，使用帶有必要連線參數的
 *       SQLite 檔案。會建立上層資料夾；在 POSIX 系統上，新檔案只有擁有者
 *       可以讀寫，因為其中存放 token 與加密後的金鑰。</li>
 * </ul>
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

    /**
     * Default Flyway location of the shipped migrations.
     * <p>
     * 隨附 migration 的預設 Flyway 位置。
     */
    public static final String MIGRATION_LOCATION = "classpath:db/migration/jacky917-as/{vendor}";

    private static final String DEFAULT_PATH = "./data/jacky917-auth.db";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (!environment.getProperty(AuthorizationServerProperties.PREFIX + ".enabled", Boolean.class, true)) {
            return;
        }
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("spring.flyway.locations", MIGRATION_LOCATION);
        if (!StringUtils.hasText(environment.getProperty("spring.datasource.url"))) {
            Path path = Path.of(environment.getProperty(
                    AuthorizationServerProperties.PREFIX + ".database.sqlite.path", DEFAULT_PATH));
            prepareDatabaseFile(path);
            defaults.put("spring.datasource.url",
                    "jdbc:sqlite:" + path + "?" + SqliteDialect.RECOMMENDED_URL_PARAMETERS);
            // 寫入依序執行，連線再多也只是排隊；維持較小的連線池
            defaults.put("spring.datasource.hikari.maximum-pool-size", 4);
        }
        environment.getPropertySources().addLast(new MapPropertySource(PROPERTY_SOURCE_NAME, defaults));
    }

    private static void prepareDatabaseFile(Path path) {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            if (Files.notExists(path) && FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("Cannot create the SQLite database file " + path.toAbsolutePath(), ex);
        }
    }
}
