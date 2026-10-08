package jacky917.security.authorizationserver.admin;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Turns the errors of the administration API controllers into RFC 9457
 * Problem Details.
 * <p>
 * 把管理 API controller 的錯誤轉為 RFC 9457 Problem Details。
 * <p>
 * Only the controllers in this package are covered, so the application's own
 * controllers keep their error handling.
 * <p>
 * 只處理此套件中的 controller，應用程式自己的 controller 維持原本的錯誤處理。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
@RestControllerAdvice(basePackageClasses = AdminApiExceptionHandler.class)
public class AdminApiExceptionHandler {

    /**
     * Turns a refused request into Problem Details with its status and
     * field errors.
     * <p>
     * 把被拒絕的請求轉為帶有狀態碼與欄位錯誤的 Problem Details。
     *
     * @param ex  the refusal
     *            <br>拒絕原因
     * @return the problem
     *         <br>Problem Details
     */
    @ExceptionHandler(AdminApiException.class)
    public ProblemDetail refused(AdminApiException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(ex.status(), ex.getMessage());
        if (!ex.errors().isEmpty()) {
            problem.setProperty("errors", ex.errors());
        }
        return problem;
    }

    /**
     * Returns {@code 400} for a body that is not valid JSON for the
     * endpoint.
     * <p>
     * 本文不是此端點可接受的 JSON 時回傳 {@code 400}。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 400} problem
     *         <br>{@code 400} 的 Problem Details
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail unreadable(HttpMessageNotReadableException ex) {
        log.debug("Unreadable administration request body", ex);
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                "The request body is not valid JSON for this endpoint");
    }

    /**
     * Returns {@code 400} with the field error for a query parameter or path
     * variable of the wrong type.
     * <p>
     * 查詢參數或路徑變數的型別錯誤時，回傳帶有欄位錯誤的 {@code 400}。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 400} problem
     *         <br>{@code 400} 的 Problem Details
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail mismatch(MethodArgumentTypeMismatchException ex) {
        Class<?> type = ex.getRequiredType();
        return refused(AdminApiException.invalid(ex.getName(), type == null ? "has the wrong type"
                : "must be a valid " + type.getSimpleName()));
    }

    /**
     * Returns {@code 400} with the field error for a missing query
     * parameter.
     * <p>
     * 缺少查詢參數時，回傳帶有欄位錯誤的 {@code 400}。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 400} problem
     *         <br>{@code 400} 的 Problem Details
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ProblemDetail missing(MissingServletRequestParameterException ex) {
        return refused(AdminApiException.invalid(ex.getParameterName(), "required"));
    }

    /**
     * Returns {@code 409} when a unique constraint is violated, for example
     * a username or email that another user already has.
     * <p>
     * 違反唯一約束時回傳 {@code 409}，例如帳號或 Email 已屬於其他使用者。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 409} problem
     *         <br>{@code 409} 的 Problem Details
     */
    @ExceptionHandler(DuplicateKeyException.class)
    public ProblemDetail duplicate(DuplicateKeyException ex) {
        log.info("Administration request hit a unique constraint: {}", ex.getMostSpecificCause().getMessage());
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
                "A value that must be unique, such as the username or email, is already used");
    }

    /**
     * Returns {@code 409} when another constraint of the database refuses
     * the change, for example a row that another request changed at the
     * same time. The request is not saved.
     * <p>
     * 資料庫的其他約束拒絕變更時回傳 {@code 409}，例如另一個請求同時變更了同一
     * 筆資料。這次請求不會儲存。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 409} problem
     *         <br>{@code 409} 的 Problem Details
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail constraint(DataIntegrityViolationException ex) {
        log.warn("Administration request refused by a database constraint", ex);
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
                "The change conflicts with the stored data; reload it and try again");
    }
}
