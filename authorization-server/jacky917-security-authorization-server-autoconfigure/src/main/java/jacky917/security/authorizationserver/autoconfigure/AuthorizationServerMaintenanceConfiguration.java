package jacky917.security.authorizationserver.autoconfigure;

import jacky917.security.authorizationserver.keys.SigningKeyService;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.maintenance.CleanupTarget;
import jacky917.security.authorizationserver.maintenance.DataCleanup;
import jacky917.security.authorizationserver.maintenance.MaintenanceScheduler;
import jacky917.security.authorizationserver.maintenance.ScheduledJobLock;
import jacky917.security.authorizationserver.maintenance.SigningKeyRotation;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Scheduled jobs of the authorization server: signing key rotation and
 * cleanup of expired data (detailed design §5.7, §5.8).
 * <p>
 * Authorization Server 的排程工作：簽章金鑰輪換與過期資料清理（詳細設計
 * §5.7、§5.8）。
 * <p>
 * {@code keys.rotation-enabled=false} turns off the rotation and
 * {@code cleanup.enabled=false} the cleanup; the beans that do the work stay
 * available, for example to run them from an administration task.
 * <p>
 * {@code keys.rotation-enabled=false} 關閉金鑰輪換，{@code cleanup.enabled=false}
 * 關閉清理；執行工作的 Bean 仍然存在，例如可供管理工作呼叫。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerMaintenanceConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    ScheduledJobLock scheduledJobLock(JdbcClient jdbcClient, Clock clock) {
        return new ScheduledJobLock(jdbcClient, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    SigningKeyRotation signingKeyRotation(SigningKeyStore store, SigningKeyService keys,
                                          PlatformTransactionManager transactionManager,
                                          AuthorizationServerProperties properties, Clock clock) {
        AuthorizationServerProperties.Keys settings = properties.getKeys();
        return new SigningKeyRotation(store, keys, new TransactionTemplate(transactionManager),
                settings.getRotationPeriod(), settings.getAnnouncePeriod(), properties.getToken().getAccessTokenTtl(),
                clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    DataCleanup dataCleanup(JdbcClient jdbcClient, SigningKeyStore keys, AuthorizationServerProperties properties,
                            ApplicationEventPublisher events, Clock clock) {
        AuthorizationServerProperties.Cleanup cleanup = properties.getCleanup();
        return new DataCleanup(jdbcClient, keys, cleanup.getBatchSize(), cleanup.getLoginAuditRetention(),
                cleanup.getAdminAuditRetention(), events, clock);
    }

    /**
     * Schedules the jobs that are turned on.
     * <p>
     * 排程已啟用的工作。
     *
     * @param lock        lets one instance run each job per period
     *                    <br>讓每個週期只有一個實例執行工作
     * @param rotation    the key rotation
     *                    <br>金鑰輪換
     * @param cleanup     the cleanup
     *                    <br>清理
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @param events      publishes a {@code MaintenanceFailedEvent} when a
     *                    job fails
     *                    <br>工作失敗時發布 {@code MaintenanceFailedEvent}
     * @param clock       the clock
     *                    <br>時鐘
     * @return the scheduler
     *         <br>排程器
     */
    @Bean
    @ConditionalOnMissingBean
    MaintenanceScheduler maintenanceScheduler(ScheduledJobLock lock, SigningKeyRotation rotation, DataCleanup cleanup,
                                              AuthorizationServerProperties properties,
                                              ApplicationEventPublisher events, Clock clock) {
        List<MaintenanceScheduler.Job> jobs = new ArrayList<>();
        if (properties.getKeys().isRotationEnabled()) {
            jobs.add(new MaintenanceScheduler.Job("signing-key-rotation", Duration.ofHours(1), rotation::rotate));
        }
        if (properties.getCleanup().isEnabled()) {
            // 每一步各自執行：一步失敗不會跳過同一個工作的其他步驟
            jobs.add(new MaintenanceScheduler.Job("cleanup-authorizations", Duration.ofMinutes(15),
                    () -> cleanup.runEach(List.of(CleanupTarget.AUTHORIZATIONS))));
            jobs.add(new MaintenanceScheduler.Job("cleanup-sessions", Duration.ofHours(1),
                    () -> cleanup.runEach(List.of(CleanupTarget.REFRESH_TOKEN_HISTORY, CleanupTarget.EXPIRED_SESSIONS,
                            CleanupTarget.SESSIONS))));
            jobs.add(new MaintenanceScheduler.Job("cleanup-daily", Duration.ofDays(1),
                    () -> cleanup.runEach(List.of(CleanupTarget.ACTION_TOKENS, CleanupTarget.AUDITS,
                            CleanupTarget.SIGNING_KEYS))));
        }
        return new MaintenanceScheduler(MaintenanceScheduler.newTaskScheduler(), lock, jobs, events, clock);
    }
}
