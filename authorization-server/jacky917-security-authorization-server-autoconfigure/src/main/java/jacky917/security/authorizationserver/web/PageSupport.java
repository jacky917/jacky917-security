package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.jspecify.annotations.Nullable;
import org.springframework.context.MessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.ui.Model;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Text and branding shared by the starter's pages.
 * <p>
 * Starter 各頁面共用的文字與品牌設定。
 * <p>
 * The text comes from the starter's own message bundle
 * {@code jacky917/authorization-server-messages} (English by default,
 * Traditional Chinese), so it neither overrides nor depends on the
 * application's {@code MessageSource}.
 * <p>
 * 文字取自 starter 自己的訊息檔 {@code jacky917/authorization-server-messages}
 * （預設英文，另有繁體中文），不覆蓋、也不依賴應用程式的 {@code MessageSource}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PageSupport {

    /**
     * The content security policy of the authorization server's pages:
     * resources and framing only from this server, images also from
     * {@code https} addresses. It has no {@code form-action}, because
     * browsers apply it to the redirects after a form, and the login and
     * consent forms end at a client's redirect URI.
     * <p>
     * Authorization Server 頁面的內容安全政策：資源與嵌入只限本伺服器，圖片另
     * 可來自 {@code https} 網址。不設 {@code form-action}，因為瀏覽器會把它
     * 套用到表單之後的重導，而登入與同意表單最後都會導向 client 的
     * redirect URI。
     */
    public static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'";

    private final AuthorizationServerProperties.Branding branding;
    private final MessageSource messages;

    /**
     * Creates the support with the given branding.
     * <p>
     * 以指定的品牌設定建立。
     *
     * @param branding  the login page appearance
     *                  <br>登入頁外觀
     */
    public PageSupport(AuthorizationServerProperties.Branding branding) {
        this.branding = branding;
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("jacky917/authorization-server-messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        this.messages = source;
    }

    /**
     * Returns one message in the given language.
     * <p>
     * 以指定語言回傳一則訊息。
     *
     * @param key        the message key
     *                   <br>訊息 key
     * @param arguments  the message arguments, or {@code null}
     *                   <br>訊息參數，或 {@code null}
     * @param locale     the language
     *                   <br>語言
     * @return the message
     *         <br>訊息
     */
    public String message(String key, Object @Nullable [] arguments, Locale locale) {
        return messages.getMessage(key, arguments, locale);
    }

    /**
     * Adds the page text, the language and the branding to a view model.
     * <p>
     * 把頁面文字、語言與品牌設定加入畫面資料。
     *
     * @param model   the view model
     *                <br>畫面資料
     * @param locale  the language of the request
     *                <br>請求的語言
     * @param keys    the message keys the page uses; available as
     *                {@code text[key]}
     *                <br>頁面使用的訊息 key，以 {@code text[key]} 取用
     */
    public void populate(Model model, Locale locale, String... keys) {
        Map<String, String> text = new LinkedHashMap<>();
        for (String key : keys) {
            text.put(key, messages.getMessage(key, null, locale));
        }
        model.addAttribute("text", text);
        model.addAttribute("lang", locale.toLanguageTag());
        model.addAttribute("productName", branding.getProductName());
        model.addAttribute("logoUrl", branding.getLogoUrl());
    }
}
