package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 讀取資料庫的表、欄位、索引與具名約束，名稱一律轉成小寫，供兩種資料庫互相比對。
 * <p>
 * 只比對 migration 中明確命名的索引與約束：主鍵、UNIQUE 約束自動建立的索引，以及資料庫自動命名的約束
 * 在兩種資料庫中的名稱本來就不同。
 */
record SchemaIntrospection(Set<String> tables, Map<String, Set<String>> columns, Set<String> indexes,
                           Set<String> constraints) {

    private static final Pattern NAMED_CONSTRAINT = Pattern.compile("CONSTRAINT\\s+(\\w+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXPLICIT_NAME = Pattern.compile("^(ck|ux|fk)_.*|^spring_session.*");

    static SchemaIntrospection of(String vendor, JdbcOperations jdbc) {
        return TestDatabases.SQLITE.equals(vendor) ? sqlite(jdbc) : postgresql(jdbc);
    }

    private static SchemaIntrospection sqlite(JdbcOperations jdbc) {
        Set<String> tables = lower(jdbc.queryForList("""
                SELECT name FROM sqlite_master WHERE type = 'table'
                AND name NOT LIKE 'sqlite_%' AND name NOT IN ('flyway_schema_history', 'jacky917_as_schema_history')""", String.class));
        Map<String, Set<String>> columns = new TreeMap<>();
        for (String table : tables) {
            columns.put(table, lower(jdbc.queryForList("SELECT name FROM pragma_table_info(?)", String.class, table)));
        }
        Set<String> indexes = lower(jdbc.queryForList("""
                SELECT name FROM sqlite_master WHERE type = 'index'
                AND name NOT LIKE 'sqlite_autoindex_%' AND tbl_name NOT IN ('flyway_schema_history', 'jacky917_as_schema_history')""", String.class));
        Set<String> constraints = new TreeSet<>();
        for (String sql : jdbc.queryForList("SELECT sql FROM sqlite_master WHERE type = 'table'", String.class)) {
            Matcher matcher = NAMED_CONSTRAINT.matcher(sql == null ? "" : sql);
            while (matcher.find()) {
                String name = matcher.group(1).toLowerCase(Locale.ROOT);
                if (EXPLICIT_NAME.matcher(name).matches()) {
                    constraints.add(name);
                }
            }
        }
        return new SchemaIntrospection(tables, columns, indexes, constraints);
    }

    private static SchemaIntrospection postgresql(JdbcOperations jdbc) {
        Set<String> tables = lower(jdbc.queryForList("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name NOT IN ('flyway_schema_history', 'jacky917_as_schema_history')""",
                String.class));
        Map<String, Set<String>> columns = new TreeMap<>();
        for (String table : tables) {
            columns.put(table, lower(jdbc.queryForList("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = ?""", String.class, table)));
        }
        Set<String> indexes = lower(jdbc.queryForList("""
                SELECT indexname FROM pg_indexes
                WHERE schemaname = 'public' AND tablename NOT IN ('flyway_schema_history', 'jacky917_as_schema_history')
                AND indexname NOT IN (SELECT conname FROM pg_constraint)""", String.class));
        Set<String> constraints = new TreeSet<>();
        for (String name : lower(jdbc.queryForList("""
                SELECT c.conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
                WHERE n.nspname = 'public'""", String.class))) {
            if (EXPLICIT_NAME.matcher(name).matches()) {
                constraints.add(name);
            }
        }
        return new SchemaIntrospection(tables, columns, indexes, constraints);
    }

    private static Set<String> lower(List<String> names) {
        Set<String> result = new TreeSet<>();
        names.forEach(name -> result.add(name.toLowerCase(Locale.ROOT)));
        return result;
    }
}
