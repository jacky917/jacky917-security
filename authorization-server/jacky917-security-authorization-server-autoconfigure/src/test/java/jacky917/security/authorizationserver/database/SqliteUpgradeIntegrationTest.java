package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SQLite 的升級路徑：V1_1_0 以重建資料表的方式修改 {@code login_audit} 與 {@code admin_audit_log} 的約束，
 * 既有的稽核紀錄、自動遞增的 ID 與索引都必須保留。
 */
@DisplayName("SQLite 從 1.0 升級到最新版：稽核資料保留")
class SqliteUpgradeIntegrationTest {

    @Test
    @DisplayName("1.0.6 的稽核紀錄在升級後完全相同，新的紀錄接續 ID，索引仍在，新的事件種類可以寫入")
    void keepsTheAuditWhenUpgrading() {
        SingleConnectionDataSource dataSource = new SingleConnectionDataSource(
                TestDatabases.newDatabaseUrl(TestDatabases.SQLITE), true);
        try {
            flyway(dataSource, "1.0.6").migrate();
            JdbcClient jdbc = JdbcClient.create(dataSource);
            jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, success, failure_reason, ip_address) "
                    + "VALUES (1000, 'LOGIN', 0, 'BAD_CREDENTIALS', '10.0.0.1')").update();
            jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, success, ip_address) "
                    + "VALUES (2000, 'LOGOUT', 1, '10.0.0.2')").update();
            jdbc.sql("INSERT INTO admin_audit_log (occurred_at, operator_client, action, target_type, target_id, "
                    + "after_value) VALUES (3000, 'admin-sync', 'USER_CREATED', 'USER', 'u1', '{\"a\":1}')").update();
            List<Map<String, Object>> logins = jdbc.sql("SELECT * FROM login_audit ORDER BY id").query().listOfRows();
            List<Map<String, Object>> admins = jdbc.sql("SELECT * FROM admin_audit_log ORDER BY id").query()
                    .listOfRows();

            flyway(dataSource, "latest").migrate();
            assertThat(jdbc.sql("SELECT * FROM login_audit ORDER BY id").query().listOfRows()).isEqualTo(logins);
            assertThat(jdbc.sql("SELECT * FROM admin_audit_log ORDER BY id").query().listOfRows()).isEqualTo(admins);

            jdbc.sql("INSERT INTO login_audit (occurred_at, event_type, success) VALUES (4000, 'MFA_ENABLED', 1)")
                    .update();
            jdbc.sql("INSERT INTO admin_audit_log (occurred_at, action, target_type, target_id) "
                    + "VALUES (5000, 'API_RESOURCE_CREATED', 'API_RESOURCE', 'orders-api')").update();
            assertThat(jdbc.sql("SELECT MAX(id) FROM login_audit").query(Long.class).single()).isEqualTo(3L);
            assertThat(jdbc.sql("SELECT MAX(id) FROM admin_audit_log").query(Long.class).single()).isEqualTo(2L);
            assertThat(jdbc.sql("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name IN "
                    + "('login_audit', 'admin_audit_log')").query(String.class).list())
                    .contains("ix_login_audit_ip_time", "ix_login_audit_user_time", "ix_login_audit_time",
                            "ix_admin_audit_target", "ix_admin_audit_operator");
        } finally {
            dataSource.destroy();
        }
    }

    private static Flyway flyway(SingleConnectionDataSource dataSource, String target) {
        return Flyway.configure().dataSource(dataSource)
                .locations(AuthorizationServerMigrations.LOCATION_PREFIX + TestDatabases.SQLITE)
                .table(AuthorizationServerMigrations.HISTORY_TABLE).target(target).load();
    }
}
