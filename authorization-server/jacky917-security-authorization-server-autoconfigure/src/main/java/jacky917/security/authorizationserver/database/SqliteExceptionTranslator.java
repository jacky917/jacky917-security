package jacky917.security.authorizationserver.database;

import org.jspecify.annotations.Nullable;
import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.support.SQLExceptionTranslator;

import java.sql.SQLException;

/**
 * Translates SQLite errors into Spring's {@link DataAccessException}
 * hierarchy and delegates every other error.
 * <p>
 * 將 SQLite 的錯誤轉換為 Spring 的 {@link DataAccessException} 階層，其他錯誤
 * 交給原本的轉換器。
 * <p>
 * Spring has no error codes for SQLite: the driver reports every constraint
 * violation as error code 19 with no SQL state, so Spring's default
 * translator returns an {@code UncategorizedSQLException}. Code that catches
 * {@link DuplicateKeyException} would then behave differently on SQLite
 * than on PostgreSQL. This translator reads the extended result code
 * instead.
 * <p>
 * Spring 沒有 SQLite 的錯誤碼：驅動程式回報的所有約束違反都是錯誤碼 19、沒有
 * SQL state，Spring 預設的轉換器因此回傳 {@code UncategorizedSQLException}；
 * 攔截 {@link DuplicateKeyException} 的程式在 SQLite 上的行為就會與 PostgreSQL
 * 不同。本轉換器改為讀取延伸結果碼。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SqliteExceptionTranslator implements SQLExceptionTranslator {

    private final SQLExceptionTranslator delegate;

    /**
     * Creates a translator that falls back to the given translator.
     * <p>
     * 建立轉換器，非 SQLite 的錯誤交給指定的轉換器。
     *
     * @param delegate  the translator for every other error
     *                  <br>處理其他錯誤的轉換器
     */
    public SqliteExceptionTranslator(SQLExceptionTranslator delegate) {
        this.delegate = delegate;
    }

    @Override
    public @Nullable DataAccessException translate(String task, @Nullable String sql, SQLException ex) {
        if (ex instanceof SQLiteException sqlite) {
            String message = task + "; SQL [" + sql + "]; " + ex.getMessage();
            SQLiteErrorCode code = sqlite.getResultCode();
            if (code == SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE || code == SQLiteErrorCode.SQLITE_CONSTRAINT_PRIMARYKEY) {
                return new DuplicateKeyException(message, ex);
            }
            if (code.name().startsWith("SQLITE_CONSTRAINT")) {
                return new DataIntegrityViolationException(message, ex);
            }
            if (code.name().startsWith("SQLITE_BUSY") || code.name().startsWith("SQLITE_LOCKED")) {
                return new CannotAcquireLockException(message, ex);
            }
        }
        return delegate.translate(task, sql, ex);
    }
}
