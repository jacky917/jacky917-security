package jacky917.security.authorizationserver.audit;

import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;

/**
 * Queries {@code login_audit}.
 * <p>
 * 查詢 {@code login_audit}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class LoginAuditRepository {

    private final JdbcClient jdbc;

    /**
     * Creates the repository.
     * <p>
     * 建立 repository。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public LoginAuditRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Counts the failed logins from an IP address since a given time (data
     * model §11.7).
     * <p>
     * 計算某個 IP 自指定時間以來的登入失敗次數（資料模型 §11.7）。
     *
     * @param ipAddress  the IP address
     *                   <br>IP 位址
     * @param since      the start of the window
     *                   <br>計算區間的起點
     * @return the number of failed logins
     *         <br>登入失敗次數
     */
    public int countFailedLogins(String ipAddress, Instant since) {
        return jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE ip_address = :ip AND event_type = 'LOGIN' "
                        + "AND success = :failed AND occurred_at > :since")
                .param("ip", ipAddress).param("failed", false).param("since", Timestamp.from(since))
                .query(Integer.class).single();
    }
}
