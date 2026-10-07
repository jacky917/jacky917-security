package jacky917.security.authorizationserver.user;

import java.time.Instant;
import java.util.Optional;

/**
 * Looks up and updates user accounts. The default implementation uses the
 * authorization server's database; an application can replace it.
 * <p>
 * 查詢與更新使用者帳號。預設實作使用 Authorization Server 的資料庫；應用程式
 * 可以自行替換。
 *
 * @author Jacky
 * @since 2.1.0
 */
public interface UserAccountService {

    /**
     * Finds a user by id.
     * <p>
     * 依 ID 查詢使用者。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the user, or empty
     *         <br>使用者；不存在時為空
     */
    Optional<UserAccount> findById(String userId);

    /**
     * Finds a user by login name or verified email, ignoring case.
     * <p>
     * 依登入帳號或已驗證的 Email 查詢使用者，不分大小寫。
     *
     * @param usernameOrEmail  what the user typed on the login page
     *                         <br>使用者在登入頁輸入的帳號
     * @return the user, or empty
     *         <br>使用者；不存在時為空
     */
    Optional<UserAccount> findByLogin(String usernameOrEmail);

    /**
     * Finds a user by verified email, ignoring case.
     * <p>
     * 依已驗證的 Email 查詢使用者，不分大小寫。
     *
     * @param email  the email
     *               <br>Email
     * @return the user, or empty
     *         <br>使用者；不存在時為空
     */
    Optional<UserAccount> findByVerifiedEmail(String email);

    /**
     * Creates a user with the {@code USER} role and the given roles.
     * <p>
     * 建立使用者，指派 {@code USER} 與指定的角色。
     *
     * @param user  the new user
     *              <br>新使用者的資料
     * @return the created user
     *         <br>建立完成的使用者
     * @throws IllegalArgumentException if the username or password is not
     *         valid, or a role does not exist
     *         <br>帳號或密碼不合規則、或角色不存在時
     * @throws org.springframework.dao.DuplicateKeyException if the username
     *         or email is taken
     *         <br>帳號或 Email 已被使用時
     */
    UserAccount createUser(NewUser user);

    /**
     * Records a successful login: resets the failure count and sets the
     * last login time.
     * <p>
     * 記錄登入成功：失敗次數歸零，並更新最後登入時間。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @param at      the login time
     *                <br>登入時間
     */
    void recordLoginSuccess(String userId, Instant at);

    /**
     * Replaces the stored password hash without counting it as a password
     * change, for example when re-hashing with stronger parameters.
     * <p>
     * 取代已儲存的密碼雜湊，但不視為變更密碼，例如以更高強度重新雜湊時。
     *
     * @param userId        the user id
     *                      <br>使用者 ID
     * @param passwordHash  the new encoded password
     *                      <br>新的編碼後密碼
     */
    void updatePasswordHash(String userId, String passwordHash);

    /**
     * Returns the user's current, unexpired roles and permissions (data
     * model §11.1).
     * <p>
     * 回傳使用者目前未過期的角色與權限（資料模型 §11.1）。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the roles and permissions, without prefixes
     *         <br>角色與權限，不含前綴
     */
    UserAuthorities loadAuthorities(String userId);
}
