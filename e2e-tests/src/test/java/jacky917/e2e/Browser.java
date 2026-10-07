package jacky917.e2e;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 模擬瀏覽器：保存 Cookie、不自動跟隨重導（測試逐步檢查每一次重導）。
 */
final class Browser {

    private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    private final HttpClient client = HttpClient.newBuilder()
            .cookieHandler(cookies)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    HttpResponse<String> get(URI uri) throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> postForm(URI uri, Map<String, String> form, Map<String, String> headers)
            throws IOException, InterruptedException {
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * 回傳重導目標（相對路徑依目前網址解析）。
     */
    static URI location(HttpResponse<?> response) {
        String location = response.headers().firstValue("Location")
                .orElseThrow(() -> new AssertionError("Expected a redirect, got " + response.statusCode()));
        return response.uri().resolve(location);
    }

    String cookie(String name) {
        return cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals(name))
                .map(HttpCookie::getValue).findFirst().orElse(null);
    }
}
