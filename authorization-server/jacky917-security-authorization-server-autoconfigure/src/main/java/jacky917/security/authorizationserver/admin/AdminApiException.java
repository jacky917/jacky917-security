package jacky917.security.authorizationserver.admin;

import org.springframework.http.HttpStatus;

import java.util.Map;

/**
 * A request to the administration API that cannot be carried out, returned
 * to the caller as RFC 9457 Problem Details.
 * <p>
 * 管理 API 無法執行的請求，以 RFC 9457 Problem Details 回傳給呼叫端。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AdminApiException extends RuntimeException {

    private final HttpStatus status;
    private final Map<String, String> errors;

    /**
     * Creates the exception.
     * <p>
     * 建立例外。
     *
     * @param status  the HTTP status
     *                <br>HTTP 狀態碼
     * @param detail  what went wrong, shown to the caller
     *                <br>問題的說明，回傳給呼叫端
     * @param errors  the invalid fields and why, or empty
     *                <br>無效的欄位與原因；沒有時為空
     */
    public AdminApiException(HttpStatus status, String detail, Map<String, String> errors) {
        super(detail);
        this.status = status;
        this.errors = Map.copyOf(errors);
    }

    /**
     * Creates a {@code 400 Bad Request} for invalid fields.
     * <p>
     * 為無效的欄位建立 {@code 400 Bad Request}。
     *
     * @param errors  the invalid fields and why
     *                <br>無效的欄位與原因
     * @return the exception
     *         <br>例外
     */
    public static AdminApiException invalid(Map<String, String> errors) {
        return new AdminApiException(HttpStatus.BAD_REQUEST, "The request has invalid fields", errors);
    }

    /**
     * Creates a {@code 400 Bad Request} for one invalid field.
     * <p>
     * 為一個無效的欄位建立 {@code 400 Bad Request}。
     *
     * @param field   the field
     *                <br>欄位
     * @param reason  why it is invalid
     *                <br>無效的原因
     * @return the exception
     *         <br>例外
     */
    public static AdminApiException invalid(String field, String reason) {
        return invalid(Map.of(field, reason));
    }

    /**
     * Creates a {@code 404 Not Found}.
     * <p>
     * 建立 {@code 404 Not Found}。
     *
     * @param what  what was not found, for example {@code User u-1}
     *              <br>找不到的對象，例如 {@code User u-1}
     * @return the exception
     *         <br>例外
     */
    public static AdminApiException notFound(String what) {
        return new AdminApiException(HttpStatus.NOT_FOUND, what + " does not exist", Map.of());
    }

    /**
     * Creates a {@code 409 Conflict}: the request is valid but clashes with
     * the current data.
     * <p>
     * 建立 {@code 409 Conflict}：請求本身有效，但與目前的資料衝突。
     *
     * @param detail  why
     *                <br>原因
     * @return the exception
     *         <br>例外
     */
    public static AdminApiException conflict(String detail) {
        return new AdminApiException(HttpStatus.CONFLICT, detail, Map.of());
    }

    /**
     * Returns the HTTP status.
     * <p>
     * 回傳 HTTP 狀態碼。
     *
     * @return the status
     *         <br>狀態碼
     */
    public HttpStatus status() {
        return status;
    }

    /**
     * Returns the invalid fields and why.
     * <p>
     * 回傳無效的欄位與原因。
     *
     * @return the errors; empty unless the status is {@code 400}
     *         <br>錯誤；狀態碼不是 {@code 400} 時為空
     */
    public Map<String, String> errors() {
        return errors;
    }
}
