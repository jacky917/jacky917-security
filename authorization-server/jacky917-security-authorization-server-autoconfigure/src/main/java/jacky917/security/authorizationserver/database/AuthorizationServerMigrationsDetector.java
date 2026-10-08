package jacky917.security.authorizationserver.database;

import org.springframework.boot.sql.init.dependency.AbstractBeansOfTypeDatabaseInitializerDetector;

import java.util.Set;

/**
 * Tells Spring Boot that {@link AuthorizationServerMigrations} initializes
 * the database, so beans that depend on database initialization (for
 * example {@code JdbcTemplate}) are created after the migrations.
 * <p>
 * 讓 Spring Boot 知道 {@link AuthorizationServerMigrations} 負責初始化資料庫，
 * 依賴資料庫初始化的 bean（例如 {@code JdbcTemplate}）因此會在 migration
 * 完成後才建立。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AuthorizationServerMigrationsDetector extends AbstractBeansOfTypeDatabaseInitializerDetector {

    @Override
    protected Set<Class<?>> getDatabaseInitializerBeanTypes() {
        return Set.of(AuthorizationServerMigrations.class);
    }
}
