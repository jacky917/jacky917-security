package jacky917.security.authorizationserver.client;

import java.net.URI;
import java.util.Set;

/**
 * Checks the addresses of a client, the same way for clients in the
 * configuration and clients created through the administration API.
 * <p>
 * 檢查 client 的網址；設定檔中的 client 與透過管理 API 建立的 client 使用相同
 * 的規則。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class ClientUris {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    private ClientUris() {
    }

    /**
     * Returns whether an address can be a redirect URI: an absolute
     * {@code https} URL without a fragment ({@code http} only for
     * {@code localhost}), or a reverse-domain scheme of a native app such as
     * {@code com.example.app:/callback} (RFC 8252 §7.1).
     * <p>
     * 回傳網址是否可作為 redirect URI：沒有 fragment 的絕對 {@code https} 網址
     * （{@code http} 只限 {@code localhost}），或原生 App 的反向網域名稱 scheme，
     * 例如 {@code com.example.app:/callback}（RFC 8252 §7.1）。
     *
     * @param uri  the address
     *             <br>網址
     * @return {@code true} if it is allowed
     *         <br>允許時為 {@code true}
     */
    public static boolean isAllowedRedirect(String uri) {
        try {
            URI parsed = URI.create(uri);
            if (!parsed.isAbsolute() || parsed.getFragment() != null) {
                return false;
            }
            String scheme = parsed.getScheme();
            // RFC 8252 §7.1：原生 App 的私有 scheme 必須是反向網域名稱（含 "."），例如 com.example.app:/callback
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return scheme.contains(".");
            }
            return isWebUrl(uri);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Returns whether an address is a web page users can open: an absolute
     * {@code https} URL without a fragment, or {@code http} on
     * {@code localhost}. Used for the logo, home page, privacy policy and
     * terms of service.
     * <p>
     * 回傳網址是否為使用者可以開啟的網頁：沒有 fragment 的絕對 {@code https}
     * 網址，或 {@code localhost} 上的 {@code http}。用於 Logo、首頁、隱私權政策
     * 與服務條款。
     *
     * @param uri  the address
     *             <br>網址
     * @return {@code true} if it is allowed
     *         <br>允許時為 {@code true}
     */
    public static boolean isWebUrl(String uri) {
        try {
            URI parsed = URI.create(uri);
            if (!parsed.isAbsolute() || parsed.getFragment() != null || parsed.getHost() == null) {
                return false;
            }
            return "https".equals(parsed.getScheme())
                    || "http".equals(parsed.getScheme()) && LOCAL_HOSTS.contains(parsed.getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}
