package jacky917.security.authorizationserver.keys;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Storage of signing keys. The default implementation uses the
 * authorization server's database; an application can replace it, for
 * example with a key management service.
 * <p>
 * 簽章金鑰的儲存。預設實作使用 Authorization Server 的資料庫；應用程式可以
 * 自行替換，例如改用金鑰管理服務。
 *
 * @author Jacky
 * @since 2.1.0
 */
public interface SigningKeyStore {

    /**
     * Returns the keys published in the JWKS: {@code NEXT},
     * {@code ACTIVE}, and {@code RETIRING}.
     * <p>
     * 回傳公開於 JWKS 的金鑰：{@code NEXT}、{@code ACTIVE}、{@code RETIRING}。
     *
     * @return the publishable keys
     *         <br>可公開的金鑰
     */
    List<SigningKey> findPublishable();

    /**
     * Returns the key that signs new tokens.
     * <p>
     * 回傳用來簽發新 token 的金鑰。
     *
     * @return the active key, or empty before the first key is created
     *         <br>目前的金鑰；尚未建立任何金鑰時為空
     */
    Optional<SigningKey> findActive();

    /**
     * Stores a new key.
     * <p>
     * 儲存新的金鑰。
     *
     * @param key  the key to store
     *             <br>要儲存的金鑰
     * @throws org.springframework.dao.DuplicateKeyException if the key would
     *         be a second {@code ACTIVE} or {@code NEXT} key
     *         <br>若會出現第二把 {@code ACTIVE} 或 {@code NEXT} 金鑰
     */
    void save(SigningKey key);

    /**
     * Moves a key from one status to another, recording the time.
     * <p>
     * 將金鑰從一個狀態改為另一個狀態，並記錄時間。
     *
     * @param kid   the key id
     *              <br>金鑰識別碼
     * @param from  the expected current status
     *              <br>預期的目前狀態
     * @param to    the new status
     *              <br>新狀態
     * @param at    the time of the change
     *              <br>變更時間
     * @return {@code true} if the key was in {@code from} and has been
     *         changed; {@code false} if another instance changed it first
     *         <br>金鑰原本為 {@code from} 且已變更時為 {@code true}；被其他
     *         實例先變更時為 {@code false}
     */
    boolean transition(String kid, SigningKeyStatus from, SigningKeyStatus to, Instant at);

    /**
     * Returns the keys in a status, oldest first.
     * <p>
     * 回傳某個狀態的金鑰，最早建立的在前。
     *
     * @param status  the status
     *                <br>狀態
     * @return the keys; empty if there is none
     *         <br>金鑰；沒有時為空
     */
    List<SigningKey> findByStatus(SigningKeyStatus status);

    /**
     * Deletes the keys retired before a given time.
     * <p>
     * 刪除在指定時間之前已退役的金鑰。
     *
     * @param before  the cutoff
     *                <br>截止時間
     * @return the number of deleted keys
     *         <br>刪除的金鑰數
     */
    int deleteRetiredBefore(Instant before);
}
