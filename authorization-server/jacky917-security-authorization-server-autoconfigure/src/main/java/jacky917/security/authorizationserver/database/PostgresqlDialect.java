package jacky917.security.authorizationserver.database;

import javax.sql.DataSource;

/**
 * Dialect for PostgreSQL 16 or later.
 * <p>
 * PostgreSQL 16 以上的方言。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PostgresqlDialect implements AuthorizationServerDialect {

    @Override
    public String vendor() {
        return "postgresql";
    }

    @Override
    public String lockAuthorizationByRefreshTokenSql() {
        return "SELECT id FROM oauth2_authorization WHERE refresh_token_value = ? FOR UPDATE";
    }

    @Override
    public boolean supportsMultipleInstances() {
        return true;
    }

    @Override
    public void validate(DataSource dataSource) {
        // 沒有額外需求：PostgreSQL 預設即檢查外鍵、支援列鎖
    }
}
