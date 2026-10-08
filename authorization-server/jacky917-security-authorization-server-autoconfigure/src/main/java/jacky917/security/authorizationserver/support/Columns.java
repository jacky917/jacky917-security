package jacky917.security.authorizationserver.support;

import org.jspecify.annotations.Nullable;

/**
 * Maximum lengths of the text columns that store values coming from
 * outside (identity providers, browsers), and truncation to fit them.
 * <p>
 * 存放外部來源值（身分提供者、瀏覽器）之文字欄位的長度上限，以及截斷以符合長度。
 * <p>
 * The lengths match the migrations (data model §4, §7). Values longer than
 * the column are truncated instead of failing the login.
 * <p>
 * 長度與 migration 一致（資料模型 §4、§7）。超過欄位長度的值會被截斷，而不是讓
 * 登入失敗。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class Columns {

    /**
     * {@code display_name}.
     */
    public static final int DISPLAY_NAME = 128;

    /**
     * {@code avatar_url}.
     */
    public static final int AVATAR_URL = 1024;

    /**
     * {@code app_user.locale}.
     */
    public static final int LOCALE = 16;

    /**
     * {@code ip_address}: the longest IPv6 text form.
     * <p>
     * {@code ip_address}：IPv6 文字格式的最大長度。
     */
    public static final int IP_ADDRESS = 45;

    /**
     * {@code user_agent}.
     */
    public static final int USER_AGENT = 512;

    private Columns() {
    }

    /**
     * Shortens a value to at most {@code maxLength} characters, never
     * splitting a character outside the Basic Multilingual Plane (such as an
     * emoji) in half.
     * <p>
     * 把值縮短為最多 {@code maxLength} 個字元，不會把基本多文種平面以外的字元
     * （例如 emoji）切成一半。
     *
     * @param value      the value, or {@code null}
     *                   <br>值，或 {@code null}
     * @param maxLength  the column length
     *                   <br>欄位長度
     * @return the value, shortened if needed
     *         <br>必要時縮短後的值
     */
    public static @Nullable String truncate(@Nullable String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        int end = Character.isHighSurrogate(value.charAt(maxLength - 1)) ? maxLength - 1 : maxLength;
        return value.substring(0, end);
    }
}
