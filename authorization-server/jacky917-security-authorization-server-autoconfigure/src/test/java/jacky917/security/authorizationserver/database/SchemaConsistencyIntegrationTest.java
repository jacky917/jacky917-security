package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 兩份 migration 必須描述同一個結構：表、欄位、索引與具名約束的名稱完全相同（詳細設計 T-DB-04）。
 * 只修改其中一份 migration 時，這個測試會失敗。
 */
@DisplayName("SQLite 與 PostgreSQL 的 schema 一致性")
class SchemaConsistencyIntegrationTest {

    @Test
    @DisplayName("表、欄位、索引、具名約束完全相同")
    void schemasMatch() {
        SchemaIntrospection sqlite = introspect(TestDatabases.SQLITE);
        SchemaIntrospection postgresql = introspect(TestDatabases.POSTGRESQL);

        assertThat(sqlite.tables()).hasSize(DatabaseMigrationIntegrationTest.TABLES.size());
        assertThat(sqlite.tables()).isEqualTo(postgresql.tables());
        assertThat(sqlite.columns()).isEqualTo(postgresql.columns());
        assertThat(sqlite.indexes()).isEqualTo(postgresql.indexes());
        assertThat(sqlite.constraints()).isNotEmpty().isEqualTo(postgresql.constraints());
    }

    private static SchemaIntrospection introspect(String vendor) {
        AtomicReference<SchemaIntrospection> result = new AtomicReference<>();
        TestDatabases.runner(vendor).run(context ->
                result.set(SchemaIntrospection.of(vendor, context.getBean(JdbcOperations.class))));
        return result.get();
    }
}
