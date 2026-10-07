package jacky917.security.authorizationserver.database;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;
import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.QueryTimeoutException;

import java.sql.SQLException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SqliteExceptionTranslator")
class SqliteExceptionTranslatorTest {

    private static final QueryTimeoutException DELEGATED = new QueryTimeoutException("delegated");
    private final SqliteExceptionTranslator translator = new SqliteExceptionTranslator((task, sql, ex) -> DELEGATED);

    static Stream<Arguments> codes() {
        return Stream.of(
                Arguments.of(SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE, DuplicateKeyException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_CONSTRAINT_PRIMARYKEY, DuplicateKeyException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_CONSTRAINT_CHECK, DataIntegrityViolationException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_CONSTRAINT_FOREIGNKEY, DataIntegrityViolationException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_CONSTRAINT_NOTNULL, DataIntegrityViolationException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_BUSY, CannotAcquireLockException.class),
                Arguments.of(SQLiteErrorCode.SQLITE_LOCKED, CannotAcquireLockException.class));
    }

    @ParameterizedTest(name = "{0} → {1}")
    @MethodSource("codes")
    @DisplayName("依延伸結果碼轉換")
    void translatesByExtendedCode(SQLiteErrorCode code, Class<? extends DataAccessException> expected) {
        DataAccessException translated = translator.translate("insert", "INSERT ...", new SQLiteException("failed", code));
        assertThat(translated).isExactlyInstanceOf(expected).hasMessageContaining("INSERT ...");
        assertThat(translated.getCause()).isInstanceOf(SQLiteException.class);
    }

    @Test
    @DisplayName("其他 SQLite 錯誤與非 SQLite 的例外交給原本的轉換器")
    void delegatesEverythingElse() {
        assertThat(translator.translate("q", null, new SQLiteException("io", SQLiteErrorCode.SQLITE_IOERR))).isSameAs(DELEGATED);
        assertThat(translator.translate("q", null, new SQLException("postgres", "23505"))).isSameAs(DELEGATED);
    }
}
