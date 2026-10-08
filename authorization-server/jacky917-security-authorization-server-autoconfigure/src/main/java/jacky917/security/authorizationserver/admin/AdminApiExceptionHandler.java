package jacky917.security.authorizationserver.admin;

import lombok.extern.slf4j.Slf4j;
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
     * Returns a refused request.
     * <p>
     * 回傳被拒絕的請求。
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
     * Returns a body or parameter that cannot be read.
     * <p>
     * 回傳無法讀取的本文或參數。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 400} problem
     *         <br>{@code 400} 的 Problem Details
     */
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class,
            MissingServletRequestParameterException.class})
    public ProblemDetail unreadable(Exception ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "The request cannot be read: "
                + ex.getClass().getSimpleName());
    }

    /**
     * Returns a value that clashes with a unique constraint, for example a
     * second user with the same email created at the same time.
     * <p>
     * 回傳違反唯一約束的值，例如同時建立兩位相同 Email 的使用者。
     *
     * @param ex  the error
     *            <br>錯誤
     * @return a {@code 409} problem
     *         <br>{@code 409} 的 Problem Details
     */
    @ExceptionHandler(DuplicateKeyException.class)
    public ProblemDetail duplicate(DuplicateKeyException ex) {
        log.debug("Administration request hit a unique constraint", ex);
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "A value that must be unique is already used");
    }
}
