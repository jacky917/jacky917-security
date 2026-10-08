package jacky917.e2e;

import jacky917.demo.bff.BffApplication;
import jacky917.demo.resourceserver.DemoResourceServerApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 在同一個 JVM 中啟動範例應用程式的工具。三個範例都在 classpath 上，因此每個應用程式都明確關閉其他範例的自動配置，
 * 並以 {@code spring.config.name} 指定一個不存在的名稱，不載入任何 application.yml，所有設定由參數提供。
 */
final class E2eApplications implements AutoCloseable {

    static final String PASSWORD = "demo-password-123";

    static final String ENCRYPTION_KEY =
            Base64.getEncoder().encodeToString("e2e-test-only-master-key-32bytes".getBytes(StandardCharsets.UTF_8));

    /**
     * BFF 與 Resource Server 不需要 JPA，也不使用 Spring Session（只有登入服務以 JDBC 保存 Session）。
     */
    static final String NO_JPA_NO_SESSION = "--spring.autoconfigure.exclude="
            + "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration,"
            + "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration,"
            + "org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration";

    /**
     * 登入服務不需要 JPA。
     */
    static final String NO_JPA = "--spring.autoconfigure.exclude="
            + "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration,"
            + "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration";

    private final List<ConfigurableApplicationContext> applications = new ArrayList<>();

    ConfigurableApplicationContext start(Class<?> application, String... args) {
        String[] all = new String[args.length + 1];
        System.arraycopy(args, 0, all, 0, args.length);
        // 不載入任何 application.yml：三個範例的設定檔同名，在同一個 classpath 上只會讀到其中一個
        all[args.length] = "--spring.config.name=jacky917-e2e-no-config-file";
        ConfigurableApplicationContext context = new SpringApplicationBuilder(application).run(all);
        applications.add(context);
        return context;
    }

    ConfigurableApplicationContext startResourceServer(String issuer, String audience, String... extra) {
        List<String> args = new ArrayList<>(List.of(
                "--server.port=0",
                "--jacky917.security.authorization-server.enabled=false",
                "--spring.flyway.enabled=false",
                "--spring.datasource.url=jdbc:h2:mem:rs-" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1",
                "--spring.jpa.hibernate.ddl-auto=create-drop",
                "--spring.autoconfigure.exclude=org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionAutoConfiguration",
                "--spring.security.oauth2.resourceserver.jwt.issuer-uri=" + issuer,
                "--spring.security.oauth2.resourceserver.jwt.audiences=" + audience,
                "--jacky917.security.permit-all-patterns=/public/**"));
        args.addAll(List.of(extra));
        return start(DemoResourceServerApplication.class, args.toArray(String[]::new));
    }

    /**
     * BFF 逐一指定登入服務的端點：啟動時不需要登入服務。
     */
    ConfigurableApplicationContext startBff(String issuer, int resourceServerPort) {
        return start(BffApplication.class,
                "--server.port=0",
                "--jacky917.security.enabled=false",
                "--jacky917.security.authorization-server.enabled=false",
                "--spring.flyway.enabled=false",
                NO_JPA_NO_SESSION,
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
                "--demo.resource-server-url=http://localhost:" + resourceServerPort);
    }

    /**
     * 登入服務共用的參數（不含埠號與資料庫）。
     */
    static List<String> authorizationServerArgs(String issuer, String bff) {
        return List.of(
                "--server.servlet.session.cookie.name=JACKY917_AS_SESSION",
                "--jacky917.security.enabled=false",
                NO_JPA,
                "--jacky917.security.authorization-server.issuer=" + issuer,
                "--jacky917.security.authorization-server.keys.encryption-key=" + ENCRYPTION_KEY,
                "--jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
                "--jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + bff + "/login/oauth2/code/jacky917",
                "--jacky917.security.authorization-server.clients.web-bff.post-logout-redirect-uris=" + bff + "/",
                "--jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile,email",
                "--jacky917.security.authorization-server.clients.report-batch.secret=batch-secret",
                "--jacky917.security.authorization-server.clients.report-batch.grant-types=client_credentials",
                "--jacky917.security.authorization-server.clients.report-batch.scopes=report.generate",
                "--demo.users.password=" + PASSWORD);
    }

    static int port(ConfigurableApplicationContext context) {
        return Integer.parseInt(context.getEnvironment().getProperty("local.server.port"));
    }

    static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Override
    public void close() {
        applications.reversed().forEach(ConfigurableApplicationContext::close);
        applications.clear();
    }
}
