package jacky917.security.authorizationserver.user;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.util.Set;

/**
 * Creates the first administrator from
 * {@code jacky917.security.authorization-server.bootstrap-admin} when no
 * user has the {@code AS_ADMIN} role.
 * <p>
 * 在沒有任何使用者擁有 {@code AS_ADMIN} 角色時，依
 * {@code jacky917.security.authorization-server.bootstrap-admin} 建立第一位
 * 管理員。
 * <p>
 * It runs at every startup but creates the account only once, so the
 * settings can stay in place; changing the password setting later does not
 * change the stored password.
 * <p>
 * 每次啟動都會執行，但只建立一次，設定可以保留；之後修改密碼設定不會改變
 * 已儲存的密碼。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class BootstrapAdminInitializer {

    private final AuthorizationServerProperties.BootstrapAdmin settings;
    private final UserAccountService users;
    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;

    /**
     * Creates the initializer.
     * <p>
     * 建立初始化器。
     *
     * @param settings      the bootstrap administrator settings
     *                      <br>第一位管理員的設定
     * @param users         the user account service
     *                      <br>使用者帳號服務
     * @param jdbc          the JDBC client of the authorization server database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param transactions  runs the creation in one transaction
     *                      <br>在同一個交易中建立
     */
    public BootstrapAdminInitializer(AuthorizationServerProperties.BootstrapAdmin settings, UserAccountService users,
                                     JdbcClient jdbc, TransactionTemplate transactions) {
        this.settings = settings;
        this.users = users;
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    /**
     * Creates the administrator if configured and none exists.
     * <p>
     * 已設定且尚無管理員時建立管理員。
     */
    public void initialize() {
        if (!StringUtils.hasText(settings.getUsername())) {
            return;
        }
        try {
            transactions.executeWithoutResult(status -> {
                int admins = jdbc.sql("SELECT COUNT(*) FROM app_user_role ur JOIN app_role r ON r.id = ur.role_id "
                        + "WHERE r.code = 'AS_ADMIN'").query(Integer.class).single();
                if (admins == 0) {
                    String email = StringUtils.hasText(settings.getEmail()) ? settings.getEmail() : null;
                    UserAccount admin = users.createUser(new NewUser(settings.getUsername(), email, email != null,
                            settings.getPassword(), settings.getUsername(), Set.of("AS_ADMIN")));
                    if (settings.isPasswordChangeRequired()) {
                        jdbc.sql("UPDATE app_user SET password_change_required = :required WHERE id = :id")
                                .param("required", true).param("id", admin.id()).update();
                    }
                    log.info("Created the bootstrap administrator {}", admin.id());
                }
            });
        } catch (DuplicateKeyException ex) {
            throw new IllegalStateException("Cannot create the bootstrap administrator: the username or email "
                    + "is already used by another account", ex);
        }
    }
}
