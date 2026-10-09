package jacky917.security.authorizationserver.client;

import jacky917.security.core.TrustLevel;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
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
     * Returns what users see about a registered client.
     * <p>
     * 回傳使用者看到的已註冊 client 資訊。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @return the details, or empty if no profile was stored
     *         <br>client 資訊；沒有資料時為空
     */
    public Optional<ClientDetails> details(String registeredClientId) {
        return jdbc.sql("SELECT description, logo_url, homepage_url, privacy_policy_url, terms_url FROM client_profile "
                        + "WHERE registered_client_id = :id")
                .param("id", registeredClientId)
                .query((rs, rowNum) -> new ClientDetails(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5)))
                .optional();
    }

    /**
     * Creates the profile, or updates everything but its status. The
     * status is kept, so a suspended client stays suspended.
     * <p>
     * 建立 client 資料，或更新狀態以外的所有欄位。狀態維持不變，已停權的
     * client 仍維持停權。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @param trustLevel          the trust level
     *                            <br>信任等級
     * @param displayName         the name shown to users
     *                            <br>顯示給使用者的名稱
     * @param details             what users see about the client
     *                            <br>使用者看到的 client 資訊
     * @param now                 the current time
     *                            <br>目前時間
     */
    public void createOrUpdate(String registeredClientId, TrustLevel trustLevel, String displayName,
                               ClientDetails details, Instant now) {
        Timestamp at = Timestamp.from(now);
        int updated = jdbc.sql("UPDATE client_profile SET trust_level = :trust, display_name = :name, "
                        + "description = :description, logo_url = :logo, homepage_url = :homepage, "
                        + "privacy_policy_url = :privacy, terms_url = :terms, updated_at = :at "
                        + "WHERE registered_client_id = :id")
                .param("trust", trustLevel.name()).param("name", displayName)
                .params(detailParams(details)).param("at", at).param("id", registeredClientId).update();
        if (updated == 0) {
            create(registeredClientId, trustLevel, displayName, details, ClientStatus.ACTIVE, now);
        }
    }

    /**
     * Creates the profile of a new client with the given status.
     * <p>
     * 以指定的狀態建立新 client 的資料。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @param trustLevel          the trust level
     *                            <br>信任等級
     * @param displayName         the name shown to users
     *                            <br>顯示給使用者的名稱
     * @param details             what users see about the client
     *                            <br>使用者看到的 client 資訊
     * @param status              the status
     *                            <br>狀態
     * @param now                 the current time
     *                            <br>目前時間
     */
    public void create(String registeredClientId, TrustLevel trustLevel, String displayName, ClientDetails details,
                       ClientStatus status, Instant now) {
        Timestamp at = Timestamp.from(now);
        jdbc.sql("INSERT INTO client_profile (registered_client_id, trust_level, display_name, description, logo_url, "
                        + "homepage_url, privacy_policy_url, terms_url, status, created_at, updated_at) VALUES (:id, "
                        + ":trust, :name, :description, :logo, :homepage, :privacy, :terms, :status, :at, :at)")
                .param("id", registeredClientId).param("trust", trustLevel.name()).param("name", displayName)
                .params(detailParams(details)).param("status", status.name()).param("at", at).update();
    }

    /**
     * Changes the status of a client.
     * <p>
     * 變更 client 的狀態。
     *
     * @param registeredClientId  the {@code oauth2_registered_client.id}
     *                            <br>{@code oauth2_registered_client.id}
     * @param status              the new status
     *                            <br>新的狀態
     * @param now                 the current time
     *                            <br>目前時間
     */
    public void updateStatus(String registeredClientId, ClientStatus status, Instant now) {
        jdbc.sql("UPDATE client_profile SET status = :status, updated_at = :at WHERE registered_client_id = :id")
                .param("status", status.name()).param("at", Timestamp.from(now)).param("id", registeredClientId)
                .update();
    }

    private static Map<String, @Nullable Object> detailParams(ClientDetails details) {
        Map<String, @Nullable Object> params = new HashMap<>();
        params.put("description", details.description());
        params.put("logo", details.logoUrl());
        params.put("homepage", details.homepageUrl());
        params.put("privacy", details.privacyPolicyUrl());
        params.put("terms", details.termsUrl());
        return params;
    }
}
