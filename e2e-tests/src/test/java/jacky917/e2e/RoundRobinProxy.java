package jacky917.e2e;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;

/**
 * 模擬負載平衡器：依序把每個請求轉給下一個後端（輪流），並加上 {@code X-Forwarded-*} 標頭。
 * 不保留黏性：所有經過代理的請求（瀏覽器、BFF、Resource Server）共用一個計數器輪流分配，
 * 同一個瀏覽器的請求因此會分散到不同的實例上。
 */
final class RoundRobinProxy implements AutoCloseable {

    private static final Set<String> HOP_BY_HOP = Set.of("host", "connection", "content-length", "expect", "upgrade",
            "transfer-encoding", "keep-alive", "te", "trailer", "proxy-connection");

    private final HttpServer server;
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final List<Integer> backends = new CopyOnWriteArrayList<>();
    private final AtomicInteger next = new AtomicInteger();
    private final AtomicIntegerArray hits = new AtomicIntegerArray(8);

    private RoundRobinProxy() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        server.createContext("/", this::forward);
        server.start();
    }

    static RoundRobinProxy start() {
        return new RoundRobinProxy();
    }

    int port() {
        return server.getAddress().getPort();
    }

    void addBackend(int port) {
        backends.add(port);
    }

    /**
     * 回傳第 {@code index} 個後端處理過的請求數。
     */
    int hits(int index) {
        return hits.get(index);
    }

    private void forward(HttpExchange exchange) throws IOException {
        int index = Math.floorMod(next.getAndIncrement(), backends.size());
        hits.incrementAndGet(index);
        URI target = URI.create("http://localhost:" + backends.get(index) + exchange.getRequestURI());
        byte[] body = exchange.getRequestBody().readAllBytes();
        HttpRequest.Builder request = HttpRequest.newBuilder(target)
                .method(exchange.getRequestMethod(), body.length == 0
                        ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        exchange.getRequestHeaders().forEach((name, values) -> {
            if (!HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                values.forEach(value -> request.header(name, value));
            }
        });
        request.header("X-Forwarded-Host", "localhost:" + port());
        request.header("X-Forwarded-Port", String.valueOf(port()));
        request.header("X-Forwarded-Proto", "http");
        HttpResponse<byte[]> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IOException(ex);
        }
        response.headers().map().forEach((name, values) -> {
            if (!HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT)) && !name.startsWith(":")) {
                exchange.getResponseHeaders().put(name, values);
            }
        });
        byte[] responseBody = response.body();
        exchange.sendResponseHeaders(response.statusCode(), responseBody.length == 0 ? -1 : responseBody.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(responseBody);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
