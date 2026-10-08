package jacky917.security.authorizationserver.database;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Wraps the exception translator of every {@link JdbcTemplate} bean with
 * {@link SqliteExceptionTranslator}.
 * <p>
 * 以 {@link SqliteExceptionTranslator} 包裝每個 {@link JdbcTemplate} bean 的
 * 例外轉換器。
 * <p>
 * The wrapper only handles SQLite exceptions, so it changes nothing for
 * other databases. {@code JdbcClient} and {@code NamedParameterJdbcTemplate}
 * use the wrapped template.
 * <p>
 * 包裝後只處理 SQLite 的例外，對其他資料庫沒有影響。{@code JdbcClient} 與
 * {@code NamedParameterJdbcTemplate} 都使用包裝後的 template。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SqliteExceptionTranslatorPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof JdbcTemplate template
                && !(template.getExceptionTranslator() instanceof SqliteExceptionTranslator)) {
            template.setExceptionTranslator(new SqliteExceptionTranslator(template.getExceptionTranslator()));
        }
        return bean;
    }
}
