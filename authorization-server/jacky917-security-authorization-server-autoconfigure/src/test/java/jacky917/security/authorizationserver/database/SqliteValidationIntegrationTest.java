package jacky917.security.authorizationserver.database;

import jacky917.security.authorizationserver.support.TestDatabases;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 自行設定的 SQLite URL 缺少必要參數時，啟動失敗並列出缺少的項目（詳細設計 T-DB-02）。
 */
@DisplayName("SQLite 連線設定檢查")
class SqliteValidationIntegrationTest {

    @TempDir
    Path dir;

    @Test
    @DisplayName("缺少 foreign_keys=true 時啟動失敗，訊息指出缺少的參數與建議的 URL")
    void missingForeignKeysFailsStartup() {
        String url = "jdbc:sqlite:" + dir.resolve("a.db")
                + "?journal_mode=WAL&busy_timeout=5000&transaction_mode=IMMEDIATE&date_class=INTEGER";
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("spring.datasource.url=" + url)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("foreign_keys=true is missing")
                            .hasMessageContaining("PRAGMA foreign_keys is not enabled")
                            .hasMessageContaining(SqliteDialect.RECOMMENDED_URL_PARAMETERS);
                });
    }

    @Test
    @DisplayName("沒有任何參數時，列出全部必要參數")
    void bareUrlListsEveryMissingParameter() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("spring.datasource.url=jdbc:sqlite:" + dir.resolve("b.db"))
                .run(context -> assertThat(context.getStartupFailure()).rootCause()
                        .hasMessageContaining("foreign_keys=true is missing")
                        .hasMessageContaining("journal_mode=WAL is missing")
                        .hasMessageContaining("transaction_mode=IMMEDIATE is missing")
                        .hasMessageContaining("date_class=INTEGER is missing"));
    }

    @Test
    @DisplayName("連線池關閉自動提交時啟動失敗（xerial 在 IMMEDIATE 模式下會一直持有寫入鎖）")
    void autoCommitDisabledFailsStartup() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("spring.datasource.hikari.auto-commit=false")
                .run(context -> assertThat(context.getStartupFailure()).rootCause()
                        .hasMessageContaining("spring.datasource.hikari.auto-commit must be true"));
    }

    @Test
    @DisplayName("database.dialect 可明確指定，不依 URL 判斷")
    void dialectCanBeSetExplicitly() {
        TestDatabases.runner(TestDatabases.SQLITE)
                .withPropertyValues("jacky917.security.authorization-server.database.dialect=sqlite")
                .run(context -> assertThat(context.getBean(AuthorizationServerDialect.class))
                        .isInstanceOf(SqliteDialect.class));
    }
}
