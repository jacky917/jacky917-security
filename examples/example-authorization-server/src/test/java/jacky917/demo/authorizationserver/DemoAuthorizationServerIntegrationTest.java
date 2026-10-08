package jacky917.demo.authorizationserver;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 範例登入服務以預設 SQLite 啟動：OIDC discovery 可用、示範資料已建立。
 * 測試用的資料庫位置設定在 {@code src/test/resources/config/application.yml}。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("範例登入服務整合測試")
class DemoAuthorizationServerIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Test
    @DisplayName("OIDC discovery 的 issuer 為 http://localhost:9000")
    void discovery() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:9000"));
    }

    @Test
    @DisplayName("示範使用者與角色已建立：alice 擁有角色 A")
    void demoData() {
        assertThat(jdbc.sql("SELECT r.code FROM app_user u JOIN app_user_role ur ON ur.user_id = u.id "
                        + "JOIN app_role r ON r.id = ur.role_id WHERE u.username = 'alice'")
                .query(String.class).list()).containsExactlyInAnyOrder("USER", "A");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM app_user WHERE username IN ('admin', 'bob')")
                .query(Integer.class).single()).isEqualTo(2);
    }
}
