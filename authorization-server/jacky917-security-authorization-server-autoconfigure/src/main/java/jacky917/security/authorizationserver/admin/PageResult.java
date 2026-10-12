package jacky917.security.authorizationserver.admin;

import java.util.List;

/**
 * One page of a list returned by the administration API.
 * <p>
 * 管理 API 回傳的清單中的一頁。
 *
 * @param items  the items of this page
 *               <br>這一頁的項目
 * @param page   the zero-based page number
 *               <br>頁碼，從 0 開始
 * @param size   the page size requested
 *               <br>要求的每頁筆數
 * @param total  the number of items on all pages
 *               <br>所有頁面的項目總數
 * @param <T>    the item type
 *               <br>項目型別
 * @author Jacky
 * @since 2.1.0
 */
public record PageResult<T>(List<T> items, int page, int size, long total) {

    /**
     * The largest page size accepted.
     * <p>
     * 接受的最大每頁筆數。
     */
    public static final int MAX_SIZE = 200;

    /**
     * Creates a page, copying the items.
     * <p>
     * 建立一頁，並複製項目清單。
     */
    public PageResult {
        items = List.copyOf(items);
    }

    /**
     * Checks a page request.
     * <p>
     * 檢查分頁參數。
     *
     * @param page  the zero-based page number
     *              <br>頁碼，從 0 開始
     * @param size  the page size
     *              <br>每頁筆數
     * @throws AdminApiException {@code 400} if {@code page} is negative or
     *         {@code size} is not between 1 and {@link #MAX_SIZE}
     *         <br>若 {@code page} 為負數，或 {@code size} 不在 1 與
     *         {@code MAX_SIZE} 之間，為 {@code 400}
     */
    public static void check(int page, int size) {
        if (page < 0) {
            throw AdminApiException.invalid("page", "must not be negative");
        }
        if (size < 1 || size > MAX_SIZE) {
            throw AdminApiException.invalid("size", "must be between 1 and " + MAX_SIZE);
        }
    }
}
