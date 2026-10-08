package jacky917.e2e;

import jacky917.demo.authorizationserver.DemoAuthorizationServerApplication;
import jacky917.demo.bff.BffApplication;
import jacky917.demo.resourceserver.DemoResourceServerApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 端對端測試（詳細設計 T-E2E-01、T-E2E-03）：瀏覽器 → BFF → 登入服務（帳號密碼）→ BFF → Resource Server。
 * <p>
 * 四個應用程式在同一個 JVM 中以各自的埠號啟動：登入服務、Resource Server、audience 不同的第二個
 * Resource Server、BFF。三個範例都在 classpath 上，因此每個應用程式都明確關閉其他範例的自動配置，
 * 並以 {@code spring.config.name} 指定一個不存在的名稱，不載入任何 application.yml，所有設定由參數提供。
 */
@DisplayName("端對端測試（瀏覽器 → BFF → 登入服務 → Resource Server）")
class EndToEndTest {

    private static final String PASSWORD = "demo-password-123";
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String NO_JPA = "--spring.autoconfigure.exclude="
            + "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration,"
            + "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration";

    @TempDir
    static Path dir;

    static int asPort;
    static int rsPort;
    static int otherRsPort;
    static int bffPort;
    static final List<ConfigurableApplicationContext> APPS = new ArrayList<>();

    /**
     * 只有登入服務的埠號必須事先決定（issuer 在啟動時就要固定）；其他應用程式以 server.port=0 啟動後讀回實際埠號。
     * 事先選好的埠號在登入服務綁定前被其他程式佔用時，換一個埠號重新啟動整組應用程式。
     */
    @BeforeAll
    static void startApplications() throws IOException {
        RuntimeException last = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                startAll(freePort());
                return;
            } catch (RuntimeException ex) {
                last = ex;
                stopApplications();
            }
        }
        throw last;
    }

    private static void startAll(int authorizationServerPort) {
        asPort = authorizationServerPort;
        String issuer = "http://localhost:" + asPort;

        // Resource Server 同時設定 jwk-set-uri：啟動時不需要登入服務（另一個 Resource Server 會測試 discovery）
        ConfigurableApplicationContext rs = startResourceServer(issuer, "jacky917-api",
                "--spring.security.oauth2.resourceserver.jwt.jwk-set-uri=" + issuer + "/oauth2/jwks");
        rsPort = port(rs);
        // BFF 逐一指定登入服務的端點：啟動時不需要登入服務
        ConfigurableApplicationContext bffApp = start(BffApplication.class,
                "--server.port=0",
                "--jacky917.security.enabled=false",
                "--jacky917.security.authorization-server.enabled=false",
                "--spring.flyway.enabled=false",
                NO_JPA,
                "--spring.security.oauth2.client.registration.jacky917.client-id=web-bff",
                "--spring.security.oauth2.client.registration.jacky917.client-secret=bff-secret",
                "--spring.security.oauth2.client.registration.jacky917.authorization-grant-type=authorization_code",
                "--spring.security.oauth2.client.registration.jacky917.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
                "--spring.security.oauth2.client.registration.jacky917.scope=openid,profile,email",
                "--spring.security.oauth2.client.provider.jacky917.authorization-uri=" + issuer + "/oauth2/authorize",
                "--spring.security.oauth2.client.provider.jacky917.token-uri=" + issuer + "/oauth2/token",
                "--spring.security.oauth2.client.provider.jacky917.jwk-set-uri=" + issuer + "/oauth2/jwks",
                "--spring.security.oauth2.client.provider.jacky917.user-info-uri=" + issuer + "/userinfo",
                "--spring.security.oauth2.client.provider.jacky917.user-name-attribute=sub",
                "--demo.authorization-server-url=" + issuer,
                "--demo.resource-server-url=http://localhost:" + rsPort);
        bffPort = port(bffApp);
        String bff = "http://localhost:" + bffPort;

        start(DemoAuthorizationServerApplication.class,
                "--server.port=" + asPort,
                "--server.servlet.session.cookie.name=JACKY917_AS_SESSION",
                "--jacky917.security.enabled=false",
                NO_JPA,
                "--jacky917.security.authorization-server.issuer=" + issuer,
                "--jacky917.security.authorization-server.keys.encryption-key="
                        + Base64.getEncoder().encodeToString("e2e-test-only-master-key-32bytes".getBytes(StandardCharsets.UTF_8)),
                "--jacky917.security.authorization-server.database.sqlite.path=" + dir.resolve("auth-" + asPort + ".db"),
                "--jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
                "--jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + bff + "/login/oauth2/code/jacky917",
                "--jacky917.security.authorization-server.clients.web-bff.post-logout-redirect-uris=" + bff + "/",
                "--jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile,email",
                "--jacky917.security.authorization-server.clients.report-batch.secret=batch-secret",
                "--jacky917.security.authorization-server.clients.report-batch.grant-types=client_credentials",
                "--jacky917.security.authorization-server.clients.report-batch.scopes=report.generate",
                "--demo.users.password=" + PASSWORD);

        // 第二個 Resource Server 只設定 issuer-uri：啟動時向登入服務查詢 discovery（詳細設計 T-E2E-03）
        otherRsPort = port(startResourceServer(issuer, "other-api"));
    }

    @AfterAll
    static void stopApplications() {
        APPS.reversed().forEach(ConfigurableApplicationContext::close);
        APPS.clear();
    }

    @Test
    @DisplayName("alice 經 BFF 登入後呼叫 Resource Server：200；擁有角色 A，/secure/role-a 也是 200（T-E2E-01）")
    void aliceLogsInThroughBffAndCallsTheApi() throws Exception {
        Browser browser = new Browser();
        logIn(browser, "alice");

        JsonNode me = JSON.readTree(browser.get(bff("/me")).body());
        assertThat(me.get("name").asString()).isEqualTo("Alice");
        assertThat(me.get("email").asString()).isEqualTo("alice@example.com");

        HttpResponse<String> secureMe = browser.get(bff("/api/secure/me"));
        assertThat(secureMe.statusCode()).isEqualTo(200);
        assertThat(secureMe.body()).contains(me.get("sub").asString());
        assertThat(browser.get(bff("/api/secure/role-a")).statusCode()).isEqualTo(200);
        assertThat(browser.get(bff("/api/secure/perm-bb")).statusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("bob 沒有角色 A：Resource Server 回 403，BFF 原樣轉回")
    void bobIsForbidden() throws Exception {
        Browser browser = new Browser();
        logIn(browser, "bob");
        assertThat(browser.get(bff("/api/secure/me")).statusCode()).isEqualTo(200);
        assertThat(browser.get(bff("/api/secure/role-a")).statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("Resource Server 以 issuer-uri 探索並驗證 aud：audience 不同的服務拒絕同一個 Token（T-E2E-03）")
    void audienceIsEnforced() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> token = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + asPort + "/oauth2/token"))
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("report-batch:batch-secret".getBytes()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope=report.generate"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(token.statusCode()).isEqualTo(200);
        String accessToken = JSON.readTree(token.body()).get("access_token").asString();

        assertThat(callWithToken(client, rsPort, accessToken).statusCode()).isEqualTo(200);
        assertThat(callWithToken(client, otherRsPort, accessToken).statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("登出：BFF 結束 Session，經登入服務的 /connect/logout 回到 BFF 首頁")
    void logoutEndsBothSessions() throws Exception {
        Browser browser = new Browser();
        logIn(browser, "alice");
        assertThat(browser.get(bff("/me")).statusCode()).isEqualTo(200);

        String xsrf = browser.cookie("XSRF-TOKEN");
        assertThat(xsrf).as("BFF 以 Cookie 提供 CSRF token").isNotNull();
        HttpResponse<String> logout = browser.postForm(bff("/logout"), Map.of(),
                Map.of("X-XSRF-TOKEN", xsrf, "Accept", "application/json"));
        URI asLogout = URI.create(JSON.readTree(logout.body()).get("redirect").asString());
        assertThat(asLogout.toString()).startsWith("http://localhost:" + asPort + "/connect/logout").contains("id_token_hint=");

        HttpResponse<String> back = browser.get(asLogout);
        assertThat(Browser.location(back)).isEqualTo(bff("/"));
        assertThat(browser.get(bff("/me")).statusCode()).isEqualTo(401);
        // 登入服務的 Session 也已結束：再次登入需要重新輸入帳密
        HttpResponse<String> authorize = browser.get(Browser.location(browser.get(bff("/oauth2/authorization/jacky917"))));
        assertThat(Browser.location(authorize).getPath()).isEqualTo("/login");
    }

    /**
     * 瀏覽器流程：BFF → 登入服務的授權端點 → 登入頁 → 送出帳密 → 授權碼回到 BFF → BFF 換 Token。
     */
    private void logIn(Browser browser, String username) throws Exception {
        HttpResponse<String> toAuthorize = browser.get(bff("/oauth2/authorization/jacky917"));
        URI authorize = Browser.location(toAuthorize);
        assertThat(authorize.toString()).startsWith("http://localhost:" + asPort + "/oauth2/authorize");

        URI loginPage = Browser.location(browser.get(authorize));
        assertThat(loginPage.getPath()).isEqualTo("/login");
        Matcher csrf = CSRF.matcher(browser.get(loginPage).body());
        assertThat(csrf.find()).isTrue();

        HttpResponse<String> login = browser.postForm(loginPage,
                Map.of("username", username, "password", PASSWORD, "_csrf", csrf.group(1)), Map.of());
        URI savedRequest = Browser.location(login);
        assertThat(savedRequest.getPath()).isEqualTo("/oauth2/authorize");

        URI callback = Browser.location(browser.get(savedRequest));
        assertThat(callback.toString()).startsWith("http://localhost:" + bffPort + "/login/oauth2/code/jacky917?code=");

        HttpResponse<String> done = browser.get(callback);
        assertThat(done.statusCode()).as("BFF 以授權碼換 Token 後重導").isEqualTo(302);
    }

    private static HttpResponse<String> callWithToken(HttpClient client, int port, String token) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/secure/me"))
                .header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static ConfigurableApplicationContext startResourceServer(String issuer, String audience, String... extra) {
        List<String> args = new ArrayList<>(List.of(
                "--server.port=0",
                "--jacky917.security.authorization-server.enabled=false",
                "--spring.flyway.enabled=false",
                "--spring.datasource.url=jdbc:h2:mem:rs-" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1",
                "--spring.jpa.hibernate.ddl-auto=create-drop",
                "--spring.security.oauth2.resourceserver.jwt.issuer-uri=" + issuer,
                "--spring.security.oauth2.resourceserver.jwt.audiences=" + audience,
                "--jacky917.security.permit-all-patterns=/public/**"));
        args.addAll(List.of(extra));
        return start(DemoResourceServerApplication.class, args.toArray(String[]::new));
    }

    private static int port(ConfigurableApplicationContext context) {
        return Integer.parseInt(context.getEnvironment().getProperty("local.server.port"));
    }

    private static ConfigurableApplicationContext start(Class<?> application, String... args) {
        String[] all = new String[args.length + 1];
        System.arraycopy(args, 0, all, 0, args.length);
        // 不載入任何 application.yml：三個範例的設定檔同名，在同一個 classpath 上只會讀到其中一個
        all[args.length] = "--spring.config.name=jacky917-e2e-no-config-file";
        ConfigurableApplicationContext context = new SpringApplicationBuilder(application).run(all);
        APPS.add(context);
        return context;
    }

    private static URI bff(String path) {
        return URI.create("http://localhost:" + bffPort + path);
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
