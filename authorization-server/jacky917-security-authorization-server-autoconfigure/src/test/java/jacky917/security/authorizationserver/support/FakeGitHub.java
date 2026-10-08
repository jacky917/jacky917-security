package jacky917.security.authorizationserver.support;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 以 JDK 內建 HttpServer 實作的假 GitHub（OAuth 2.0，不是 OIDC）：token、{@code /user}、{@code /user/emails}。
 * {@code /user/emails} 在沒有登記 Email 時回 403，模擬沒有 {@code user:email} scope。
 */
public final class FakeGitHub implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpServer server;
    private final Map<String, Login> logins = new ConcurrentHashMap<>();

    private FakeGitHub() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        server.createContext("/login/oauth/access_token", this::token);
        server.createContext("/user", exchange -> {
            Login login = login(exchange);
            if (login == null) {
                respond(exchange, 401, "{\"message\":\"Bad credentials\"}");
            } else if (exchange.getRequestURI().getPath().equals("/user/emails")) {
                if (login.emails() == null) {
                    respond(exchange, 403, "{\"message\":\"Resource not accessible by integration\"}");
                } else {
                    respond(exchange, 200, JSON.writeValueAsString(login.emails()));
                }
            } else {
                respond(exchange, 200, JSON.writeValueAsString(login.user()));
            }
        });
        server.start();
    }

    public static FakeGitHub start() {
        return new FakeGitHub();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * 登記一次登入：{@code /user} 的內容與 {@code /user/emails} 的清單（{@code null} 表示 403）。
     */
    public String prepare(long id, String login, String name, List<Map<String, Object>> emails) {
        String code = UUID.randomUUID().toString();
        logins.put(code, new Login(Map.of("id", id, "login", login, "name", name,
                "avatar_url", "https://avatars.example.com/" + id, "email", login + "@public.example.com"), emails));
        return code;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private Login login(HttpExchange exchange) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        return authorization == null ? null : logins.get(authorization.substring("Bearer gh-".length()));
    }

    private void token(HttpExchange exchange) throws IOException {
        String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String code = Arrays.stream(form.split("&")).filter(pair -> pair.startsWith("code="))
                .map(pair -> URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8)).findFirst().orElse("");
        if (!logins.containsKey(code)) {
            respond(exchange, 400, "{\"error\":\"bad_verification_code\"}");
            return;
        }
        respond(exchange, 200, JSON.writeValueAsString(Map.of("access_token", "gh-" + code, "token_type", "bearer",
                "scope", "read:user,user:email")));
    }

    private record Login(Map<String, Object> user, List<Map<String, Object>> emails) {
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
