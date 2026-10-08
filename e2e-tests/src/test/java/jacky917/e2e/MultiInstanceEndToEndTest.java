package jacky917.e2e;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import jacky917.demo.authorizationserver.DemoAuthorizationServerApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 多實例（D10、工作 16）：兩個登入服務共用一個 PostgreSQL，前面是輪流轉送、沒有黏性的負載平衡器。
 * 同一個瀏覽器的連續請求一定落在不同的實例上，因此登入頁的 CSRF、被中斷的授權請求、授權碼、Token、登出
 * 都必須跨實例運作：瀏覽器 Session 存在 Spring Session JDBC，授權與登入 Session 存在共用的資料庫。
 */
@DisplayName("多實例端對端測試（兩個登入服務 + PostgreSQL + Spring Session JDBC）")
class MultiInstanceEndToEndTest {

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final E2eApplications APPS = new E2eApplications();

    private static EmbeddedPostgres postgres;
    private static RoundRobinProxy proxy;
    private static JdbcClient database;
    private static String issuer;
    private static int bffPort;

    @BeforeAll
    static void startApplications() throws IOException {
        postgres = EmbeddedPostgres.start();
        String url = postgres.getJdbcUrl("postgres", "postgres");
        database = JdbcClient.create(new SingleConnectionDataSource(url, "postgres", "", true));
        proxy = RoundRobinProxy.start();
        issuer = "http://localhost:" + proxy.port();

        int rsPort = E2eApplications.port(APPS.startResourceServer(issuer, "jacky917-api",
                "--spring.security.oauth2.resourceserver.jwt.jwk-set-uri=" + issuer + "/oauth2/jwks"));
        bffPort = E2eApplications.port(APPS.startBff(issuer, rsPort));
        // 依序啟動：第二個實例看到已完成的 migration、已存在的金鑰與 client
        for (int instance = 0; instance < 2; instance++) {
            List<String> args = new ArrayList<>(E2eApplications.authorizationServerArgs(issuer, "http://localhost:" + bffPort));
            args.addAll(List.of("--server.port=0",
                    "--server.forward-headers-strategy=framework",
                    "--spring.datasource.url=" + url,
                    "--spring.datasource.username=postgres"));
            proxy.addBackend(E2eApplications.port(APPS.start(DemoAuthorizationServerApplication.class,
                    args.toArray(String[]::new))));
        }
    }

    @AfterAll
    static void stopApplications() throws IOException {
        APPS.close();
        if (proxy != null) {
            proxy.close();
        }
        if (postgres != null) {
            postgres.close();
        }
    }

    @Test
    @DisplayName("每個請求輪流落在不同實例：登入、授權碼、換 Token、呼叫 API 都成功；瀏覽器 Session 存在資料庫")
    void logInAcrossInstances() throws Exception {
        Browser browser = new Browser();
        logIn(browser, "alice");
        JsonNode me = JSON.readTree(browser.get(bff("/me")).body());
        assertThat(me.get("name").asString()).isEqualTo("Alice");
        assertThat(browser.get(bff("/api/secure/role-a")).statusCode()).isEqualTo(200);

        assertThat(proxy.hits(0)).as("第一個實例").isPositive();
        assertThat(proxy.hits(1)).as("第二個實例").isPositive();
        assertThat(database.sql("SELECT COUNT(*) FROM SPRING_SESSION").query(Integer.class).single())
                .as("登入服務的瀏覽器 Session 由 Spring Session JDBC 保存").isPositive();
    }

    @Test
    @DisplayName("帳號頁連續開啟（落在兩個實例）都顯示同一個登入；登出後兩個實例都要求重新登入、登入 Session 已撤銷")
    void accountPageAndLogoutAcrossInstances() throws Exception {
        Browser browser = new Browser();
        logIn(browser, "bob");
        for (int i = 0; i < 2; i++) {
            HttpResponse<String> account = browser.get(URI.create(issuer + "/jacky917/account"));
            assertThat(account.statusCode()).isEqualTo(200);
            assertThat(account.body()).contains("Bob");
        }

        String xsrf = browser.cookie("XSRF-TOKEN");
        HttpResponse<String> logout = browser.postForm(bff("/logout"), Map.of(),
                Map.of("X-XSRF-TOKEN", xsrf, "Accept", "application/json"));
        URI asLogout = URI.create(JSON.readTree(logout.body()).get("redirect").asString());
        assertThat(Browser.location(browser.get(asLogout))).isEqualTo(bff("/"));

        assertThat(database.sql("SELECT s.status FROM auth_session s JOIN app_user u ON u.id = s.user_id "
                        + "WHERE u.username = 'bob' ORDER BY s.created_at DESC LIMIT 1").query(String.class).single())
                .isEqualTo("REVOKED");
        for (int i = 0; i < 2; i++) {
            HttpResponse<String> account = browser.get(URI.create(issuer + "/jacky917/account"));
            assertThat(Browser.location(account).getPath()).as("兩個實例都已登出").isEqualTo("/login");
        }
    }

    private static void logIn(Browser browser, String username) throws Exception {
        URI authorize = Browser.location(browser.get(bff("/oauth2/authorization/jacky917")));
        assertThat(authorize.toString()).startsWith(issuer + "/oauth2/authorize");
        URI loginPage = Browser.location(browser.get(authorize));
        assertThat(loginPage.getPath()).isEqualTo("/login");
        Matcher csrf = CSRF.matcher(browser.get(loginPage).body());
        assertThat(csrf.find()).isTrue();
        HttpResponse<String> login = browser.postForm(loginPage,
                Map.of("username", username, "password", E2eApplications.PASSWORD, "_csrf", csrf.group(1)), Map.of());
        URI savedRequest = Browser.location(login);
        assertThat(savedRequest.toString()).as("CSRF 與被中斷的授權請求跨實例有效").startsWith(issuer + "/oauth2/authorize");
        URI callback = Browser.location(browser.get(savedRequest));
        assertThat(callback.toString()).startsWith(bff("/login/oauth2/code/jacky917?code=").toString());
        assertThat(browser.get(callback).statusCode()).as("BFF 以授權碼換 Token（落在另一個實例）").isEqualTo(302);
    }

    private static URI bff(String path) {
        return URI.create("http://localhost:" + bffPort + path);
    }
}
