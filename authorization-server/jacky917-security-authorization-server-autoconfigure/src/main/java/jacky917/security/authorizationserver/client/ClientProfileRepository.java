package jacky917.security.authorizationserver.client;

import jacky917.security.core.TrustLevel;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * Reads and writes {@code client_profile}.
 * <p>
 * 讀寫 {@code client_profile}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ClientProfileRepository {

    private final JdbcClient jdbc;

    /**
     * Creates a repository that uses the given client.
     * <p>
     * 建立使用指定 client 的 repository。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public ClientProfileRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Returns the profile of a registered client.
     * <p>
     * 回傳已註冊 client 的資料。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @return the profile, or empty if none was stored
     *         <br>client 資料；沒有資料時為空
     */
    public Optional<ClientProfile> find(String registeredClientId) {
        return jdbc.sql("SELECT registered_client_id, trust_level, display_name, status FROM client_profile "
                        + "WHERE registered_client_id = :id")
                .param("id", registeredClientId)
                .query((rs, rowNum) -> new ClientProfile(rs.getString(1), TrustLevel.valueOf(rs.getString(2)),
                        rs.getString(3), ClientStatus.valueOf(rs.getString(4))))
                .optional();
    }

    /**
     * Creates the profile, or updates its trust level and display name.
     * The status is kept, so a suspended client stays suspended.
     * <p>
     * 建立 client 資料，或更新其信任等級與顯示名稱。狀態維持不變，已停權的
     * client 仍維持停權。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @param trustLevel          the trust level
     *                            <br>信任等級
     * @param displayName         the name shown to users
     *                            <br>顯示給使用者的名稱
     * @param now                 the current time
     *                            <br>目前時間
     */
    public void createOrUpdate(String registeredClientId, TrustLevel trustLevel, String displayName, Instant now) {
        Timestamp at = Timestamp.from(now);
        int updated = jdbc.sql("UPDATE client_profile SET trust_level = :trust, display_name = :name, updated_at = :at "
                        + "WHERE registered_client_id = :id")
                .param("trust", trustLevel.name()).param("name", displayName).param("at", at)
                .param("id", registeredClientId).update();
        if (updated == 0) {
            jdbc.sql("INSERT INTO client_profile (registered_client_id, trust_level, display_name, status, created_at, "
                            + "updated_at) VALUES (:id, :trust, :name, 'ACTIVE', :at, :at)")
                    .param("id", registeredClientId).param("trust", trustLevel.name()).param("name", displayName)
                    .param("at", at).update();
        }
    }
}
