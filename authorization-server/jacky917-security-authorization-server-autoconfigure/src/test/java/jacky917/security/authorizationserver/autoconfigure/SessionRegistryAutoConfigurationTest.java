package jacky917.security.authorizationserver.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * {@link AuthorizationServerSessionRegistryAutoConfiguration}：應用程式使用 Spring Session 時，OIDC 的 Session
 * registry 改讀共用的 Session 儲存（多實例時 ID Token 才有 sid）。
 */
@DisplayName("AuthorizationServerSessionRegistryAutoConfiguration")
class SessionRegistryAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthorizationServerSessionRegistryAutoConfiguration.class));

    @Test
    @DisplayName("有 Spring Session 的 repository：註冊 SpringSessionBackedSessionRegistry")
    void usesSpringSession() {
        runner.withBean(FindByIndexNameSessionRepository.class, () -> mock(FindByIndexNameSessionRepository.class))
                .run(context -> assertThat(context).getBean(SessionRegistry.class)
                        .isInstanceOf(SpringSessionBackedSessionRegistry.class));
    }

    @Test
    @DisplayName("沒有 Spring Session、或 Authorization Server 已停用：不註冊（Spring 預設在記憶體中追蹤）")
    void backsOffWithoutSpringSession() {
        runner.run(context -> assertThat(context).doesNotHaveBean(SessionRegistry.class));
        runner.withBean(FindByIndexNameSessionRepository.class, () -> mock(FindByIndexNameSessionRepository.class))
                .withPropertyValues("jacky917.security.authorization-server.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(SessionRegistry.class));
    }
}
