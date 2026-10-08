package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

/**
 * Tracks OpenID Connect sessions with Spring Session when the application
 * stores browser sessions there, for example with
 * {@code spring-boot-starter-session-jdbc} (D10).
 * <p>
 * 應用程式把瀏覽器 Session 存放在 Spring Session 時（例如加入
 * {@code spring-boot-starter-session-jdbc}），以 Spring Session 追蹤 OpenID
 * Connect 的 Session（D10）。
 * <p>
 * Spring Authorization Server keeps its session registry in memory by
 * default. With several instances, a token request served by another
 * instance would then find no session, and the ID token would have no
 * {@code sid}. This registry reads the shared session store instead.
 * <p>
 * Spring Authorization Server 預設把 Session registry 放在記憶體中。多個實例
 * 時，由另一個實例處理的 token 請求找不到 Session，ID Token 因此沒有
 * {@code sid}。此 registry 改為讀取共用的 Session 儲存。
 *
 * @author Jacky
 * @since 2.1.0
 */
// 類別名稱已對照 Spring Boot 4.1.1 的 jar 確認（這些模組不在本模組的 classpath 上，無法以測試檢查）
@AutoConfiguration(afterName = {
        "org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration",
        "org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration",
        "org.springframework.boot.session.autoconfigure.SessionAutoConfiguration"
})
@ConditionalOnClass(FindByIndexNameSessionRepository.class)
@ConditionalOnBean(FindByIndexNameSessionRepository.class)
@ConditionalOnProperty(prefix = AuthorizationServerProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class AuthorizationServerSessionRegistryAutoConfiguration {

    /**
     * The session registry backed by the application's Spring Session
     * repository.
     * <p>
     * 以應用程式的 Spring Session repository 為後端的 Session registry。
     *
     * @param sessions  the indexed session repository
     *                  <br>可依 principal 查詢的 Session repository
     * @return the registry
     *         <br>registry
     */
    @Bean
    @ConditionalOnMissingBean
    SessionRegistry jacky917SessionRegistry(FindByIndexNameSessionRepository<? extends Session> sessions) {
        return new SpringSessionBackedSessionRegistry<>(sessions);
    }
}
