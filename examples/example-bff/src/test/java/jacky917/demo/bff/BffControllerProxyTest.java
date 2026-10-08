package jacky917.demo.bff;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * API 代理的轉送規則：路徑與 query 原樣轉送、不當成 URI 樣板、拒絕會被解讀成其他主機的路徑、
 * 原樣轉回狀態碼。以本機的假 API 伺服器記錄收到的請求（附帶 token 的部分由 e2e-tests 驗證）。
 */
@DisplayName("BFF 的 API 代理")
class BffControllerProxyTest {

    private HttpServer api;
    private final AtomicReference<String> received = new AtomicReference<>();
    private BffController controller;

    @BeforeEach
    void startApi() throws IOException {
        api = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        api.createContext("/", exchange -> {
            received.set(exchange.getRequestURI().getRawPath() + (exchange.getRequestURI().getRawQuery() == null
                    ? "" : "?" + exchange.getRequestURI().getRawQuery()));
            byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(exchange.getRequestURI().getPath().endsWith("/forbidden") ? 403 : 200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        api.start();
        String apiUrl = "http://127.0.0.1:" + api.getAddress().getPort();
        controller = new BffController(RestClient.builder().build(), new BffProperties("http://localhost:9000", apiUrl));
    }

    @AfterEach
    void stopApi() {
        api.stop(0);
    }

    @Test
    @DisplayName("路徑與 query 原樣轉送；路徑中的 { } 不當成 URI 樣板")
    void forwardsPathAndQuery() {
        ResponseEntity<String> response = controller.proxy(request("/api/secure/abac/a%7Bb%7D", "x=1&y=%20z"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo("{\"ok\":true}");
        assertThat(received.get()).isEqualTo("/secure/abac/a%7Bb%7D?x=1&y=%20z");
    }

    @Test
    @DisplayName("API 的狀態碼原樣轉回（例如 403）")
    void passesStatusThrough() {
        assertThat(controller.proxy(request("/api/secure/forbidden", null)).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("以 // 開頭的路徑（會被解讀成其他主機）直接回 400，不發出請求")
    void rejectsHostLikePaths() {
        assertThat(controller.proxy(request("/api//evil.example.com/steal", null)).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(received.get()).isNull();
    }

    private static MockHttpServletRequest request(String uri, String query) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.setQueryString(query);
        return request;
    }
}
