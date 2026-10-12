package jacky917.demo.authorizationserver;

import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Creates the demo data the examples use: the role, permissions and users
 * of {@code example-resource-server} once, and the scope of the
 * third-party demo whenever it is missing.
 * <p>
 * 建立範例使用的示範資料：{@code example-resource-server} 的角色、權限與使用者
 * 只建立一次；第三方示範的 scope 不存在時建立。
 * <ul>
 *   <li>Role {@code A} with permissions {@code bb} and {@code clip:read}.
 *       <br>角色 {@code A}，擁有權限 {@code bb} 與 {@code clip:read}。</li>
 *   <li>{@code alice} has role {@code A}; {@code bob} has only {@code USER}.
 *       <br>{@code alice} 擁有角色 {@code A}；{@code bob} 只有 {@code USER}。</li>
 *   <li>Scope {@code bb.read} grants permission {@code bb} to the
 *       third-party client {@code partner-demo}, and is shown on its
 *       consent page; it is also added to an existing demo database.
 *       <br>scope {@code bb.read} 把權限 {@code bb} 授予第三方 client
 *       {@code partner-demo}，並顯示在它的同意畫面上；既有的示範資料庫也會
 *       補上。</li>
 * </ul>
 * For demonstration only; real applications manage roles through the admin
 * API.
 * <p>
 * 僅供示範；正式環境以管理 API 管理角色。
 */
@Component
public class DemoDataInitializer implements ApplicationRunner {

    private final JdbcClient jdbc;
    private final UserAccountService users;
    private final String password;

    /**
     * Creates the initializer.
     * <p>
     * 建立初始化器。
     *
     * @param jdbc      the JDBC client of the login service database
     *                  <br>登入服務資料庫的 JDBC client
     * @param users     the user account service
     *                  <br>使用者帳號服務
     * @param password  the password of the demo users
     *                  <br>示範使用者的密碼
     */
    public DemoDataInitializer(JdbcClient jdbc, UserAccountService users,
                               @Value("${demo.users.password}") String password) {
        this.jdbc = jdbc;
        this.users = users;
        this.password = password;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        Timestamp now = Timestamp.from(Instant.now());
        if (jdbc.sql("SELECT COUNT(*) FROM app_role WHERE code = 'A'").query(Integer.class).single() == 0) {
            createRoleAndUsers(now);
        }
        if (jdbc.sql("SELECT COUNT(*) FROM app_scope WHERE code = 'bb.read'").query(Integer.class).single() == 0) {
            createPartnerScope(now);
        }
    }

    private void createPartnerScope(Timestamp now) {
        jdbc.sql("INSERT INTO app_scope (code, display_name, description, consent_required, built_in, created_at) "
                        + "VALUES ('bb.read', '使用權限 bb', '讓應用程式代您呼叫需要權限 bb 的 API', :yes, :no, :now)")
                .param("yes", true).param("no", false).param("now", now).update();
        jdbc.sql("INSERT INTO app_scope_permission (scope_code, permission_id) "
                + "SELECT 'bb.read', id FROM app_permission WHERE code = 'bb'").update();
    }

    private void createRoleAndUsers(Timestamp now) {
        String roleId = UUID.randomUUID().toString();
        jdbc.sql("INSERT INTO app_role (id, code, name, built_in, created_at, updated_at) "
                        + "VALUES (:id, 'A', 'Demo role A', :builtIn, :now, :now)")
                .param("id", roleId).param("builtIn", false).param("now", now).update();
        for (String permission : new String[]{"bb", "clip:read"}) {
            String permissionId = UUID.randomUUID().toString();
            jdbc.sql("INSERT INTO app_permission (id, code, name, built_in, created_at, updated_at) "
                            + "VALUES (:id, :code, :code, :builtIn, :now, :now)")
                    .param("id", permissionId).param("code", permission).param("builtIn", false).param("now", now)
                    .update();
            jdbc.sql("INSERT INTO app_role_permission (role_id, permission_id) VALUES (:role, :permission)")
                    .param("role", roleId).param("permission", permissionId).update();
        }
        users.createUser(new NewUser("alice", "alice@example.com", true, password, "Alice", Set.of("A")));
        users.createUser(new NewUser("bob", "bob@example.com", true, password, "Bob", Set.of()));
    }
}
