package jacky917.security.authorizationserver.keys;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * {@link SigningKeyStore} backed by the {@code signing_key} table. The SQL
 * is the same on every supported database.
 * <p>
 * 以 {@code signing_key} 表實作的 {@link SigningKeyStore}，在所有支援的資料庫上
 * 使用相同的 SQL。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class JdbcSigningKeyStore implements SigningKeyStore {

    private static final String COLUMNS = "kid, algorithm, key_size, public_key, private_key_encrypted, "
            + "encryption_key_id, status, created_at, activated_at, retiring_at, retired_at";

    private static final RowMapper<SigningKey> ROW_MAPPER = (rs, rowNum) -> new SigningKey(
            rs.getString("kid"),
            rs.getString("algorithm"),
            rs.getInt("key_size"),
            rs.getString("public_key"),
            rs.getString("private_key_encrypted"),
            rs.getString("encryption_key_id"),
            SigningKeyStatus.valueOf(rs.getString("status")),
            toInstant(rs.getTimestamp("created_at")),
            toInstant(rs.getTimestamp("activated_at")),
            toInstant(rs.getTimestamp("retiring_at")),
            toInstant(rs.getTimestamp("retired_at")));

    private final JdbcClient jdbc;

    /**
     * Creates a store that uses the given client.
     * <p>
     * 建立使用指定 client 的儲存。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public JdbcSigningKeyStore(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public List<SigningKey> findPublishable() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM signing_key WHERE status IN ('NEXT', 'ACTIVE', 'RETIRING') "
                        + "ORDER BY created_at DESC")
                .query(ROW_MAPPER).list();
    }

    @Override
    public Optional<SigningKey> findActive() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM signing_key WHERE status = 'ACTIVE'")
                .query(ROW_MAPPER).optional();
    }

    @Override
    public List<SigningKey> findByStatus(SigningKeyStatus status) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM signing_key WHERE status = :status ORDER BY created_at")
                .param("status", status.name()).query(ROW_MAPPER).list();
    }

    @Override
    public int deleteRetiredBefore(Instant before) {
        return jdbc.sql("DELETE FROM signing_key WHERE status = 'RETIRED' AND retired_at < :before")
                .param("before", Timestamp.from(before)).update();
    }

    @Override
    public void save(SigningKey key) {
        jdbc.sql("INSERT INTO signing_key (" + COLUMNS + ") VALUES (:kid, :algorithm, :keySize, :publicKey, "
                        + ":privateKey, :encryptionKeyId, :status, :createdAt, :activatedAt, :retiringAt, :retiredAt)")
                .param("kid", key.kid())
                .param("algorithm", key.algorithm())
                .param("keySize", key.keySize())
                .param("publicKey", key.publicJwk())
                .param("privateKey", key.privateKeyEncrypted())
                .param("encryptionKeyId", key.encryptionKeyId())
                .param("status", key.status().name())
                .param("createdAt", toTimestamp(key.createdAt()))
                .param("activatedAt", toTimestamp(key.activatedAt()))
                .param("retiringAt", toTimestamp(key.retiringAt()))
                .param("retiredAt", toTimestamp(key.retiredAt()))
                .update();
    }

    @Override
    public boolean transition(String kid, SigningKeyStatus from, SigningKeyStatus to, Instant at) {
        String timeColumn = switch (to) {
            case ACTIVE -> "activated_at";
            case RETIRING -> "retiring_at";
            case RETIRED -> "retired_at";
            case NEXT -> throw new IllegalArgumentException("A key cannot move back to NEXT");
        };
        return jdbc.sql("UPDATE signing_key SET status = :to, " + timeColumn + " = :at WHERE kid = :kid AND status = :from")
                .param("to", to.name())
                .param("at", Timestamp.from(at))
                .param("kid", kid)
                .param("from", from.name())
                .update() == 1;
    }

    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private static Timestamp toTimestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }
}
