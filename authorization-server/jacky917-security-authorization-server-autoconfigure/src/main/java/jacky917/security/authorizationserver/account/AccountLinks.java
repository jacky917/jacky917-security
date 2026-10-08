package jacky917.security.authorizationserver.account;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the absolute links put in account mails, from the issuer URL.
 * <p>
 * 以 issuer 網址產生放入帳號信件的完整連結。
 * <p>
 * The issuer is the public address of the authorization server, so the
 * links work behind a reverse proxy without trusting the request's host
 * header (which an attacker could set to their own site).
 * <p>
 * issuer 就是 Authorization Server 的對外網址，因此在反向代理之後連結也正確，
 * 而且不依賴請求的 Host 標頭（攻擊者可以把它設為自己的網站）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AccountLinks {

    private final String base;

    /**
     * Creates the links for the given issuer.
     * <p>
     * 為指定的 issuer 建立。
     *
     * @param issuer  the issuer, {@code issuer}
     *                <br>issuer，即 {@code issuer}
     */
    public AccountLinks(URI issuer) {
        String value = issuer.toString();
        this.base = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    /**
     * Returns the link to a page with a token.
     * <p>
     * 回傳帶有 token 的頁面連結。
     *
     * @param path   the page path, for example {@code /jacky917/password/reset}
     *               <br>頁面路徑，例如 {@code /jacky917/password/reset}
     * @param token  the token
     *               <br>token
     * @return the absolute link
     *         <br>完整的連結
     */
    public String withToken(String path, String token) {
        return base + path + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    }

    /**
     * Returns the link to a page.
     * <p>
     * 回傳頁面連結。
     *
     * @param path  the page path
     *              <br>頁面路徑
     * @return the absolute link
     *         <br>完整的連結
     */
    public String to(String path) {
        return base + path;
    }
}
