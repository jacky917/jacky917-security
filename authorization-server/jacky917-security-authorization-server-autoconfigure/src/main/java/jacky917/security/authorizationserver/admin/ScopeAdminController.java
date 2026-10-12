package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.admin.ScopeAdminService.ApiResourceRequest;
import jacky917.security.authorizationserver.admin.ScopeAdminService.ApiResourceView;
import jacky917.security.authorizationserver.admin.ScopeAdminService.ScopeRequest;
import jacky917.security.authorizationserver.admin.ScopeAdminService.ScopeView;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Scopes and API resources in the administration API (phase 3 and 4
 * design §6.4).
 * <p>
 * 管理 API 中的 scope 與 API resource（第 3、4 階段設計 §6.4）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api")
public class ScopeAdminController {

    private final ScopeAdminService scopes;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param scopes  manages scopes and API resources
     *                <br>管理 scope 與 API resource
     */
    public ScopeAdminController(ScopeAdminService scopes) {
        this.scopes = scopes;
    }

    /**
     * Lists the scopes.
     * <p>
     * 列出 scope。
     *
     * @return the scopes, by code
     *         <br>scope，依代碼排序
     */
    @GetMapping("/scopes")
    public List<ScopeView> scopes() {
        return scopes.scopes();
    }

    /**
     * Creates a scope.
     * <p>
     * 建立 scope。
     *
     * @param request  the scope
     *                 <br>scope
     * @return the scope
     *         <br>scope
     */
    @PostMapping("/scopes")
    @ResponseStatus(HttpStatus.CREATED)
    public ScopeView createScope(@RequestBody ScopeRequest request) {
        return scopes.createScope(request);
    }

    /**
     * Returns a scope.
     * <p>
     * 回傳一個 scope。
     *
     * @param code  the scope code
     *              <br>scope 代碼
     * @return the scope
     *         <br>scope
     */
    @GetMapping("/scopes/{code}")
    public ScopeView scope(@PathVariable String code) {
        return scopes.scope(code);
    }

    /**
     * Replaces a scope.
     * <p>
     * 取代 scope。
     *
     * @param code     the scope code
     *                 <br>scope 代碼
     * @param request  the new values
     *                 <br>新的值
     * @return the scope
     *         <br>scope
     */
    @PutMapping("/scopes/{code}")
    public ScopeView updateScope(@PathVariable String code, @RequestBody ScopeRequest request) {
        return scopes.updateScope(code, request);
    }

    /**
     * Deletes a scope.
     * <p>
     * 刪除 scope。
     *
     * @param code  the scope code
     *              <br>scope 代碼
     */
    @DeleteMapping("/scopes/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteScope(@PathVariable String code) {
        scopes.deleteScope(code);
    }

    /**
     * Lists the API resources.
     * <p>
     * 列出 API resource。
     *
     * @return the API resources, by code
     *         <br>API resource，依代碼排序
     */
    @GetMapping("/api-resources")
    public List<ApiResourceView> apiResources() {
        return scopes.apiResources();
    }

    /**
     * Creates an API resource.
     * <p>
     * 建立 API resource。
     *
     * @param request  the API resource
     *                 <br>API resource
     * @return the API resource
     *         <br>API resource
     */
    @PostMapping("/api-resources")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResourceView createApiResource(@RequestBody ApiResourceRequest request) {
        return scopes.createApiResource(request);
    }

    /**
     * Returns an API resource.
     * <p>
     * 回傳一個 API resource。
     *
     * @param code  the API resource code
     *              <br>API resource 代碼
     * @return the API resource
     *         <br>API resource
     */
    @GetMapping("/api-resources/{code}")
    public ApiResourceView apiResource(@PathVariable String code) {
        return scopes.apiResource(code);
    }

    /**
     * Replaces an API resource's name and description.
     * <p>
     * 取代 API resource 的名稱與說明。
     *
     * @param code     the API resource code
     *                 <br>API resource 代碼
     * @param request  the new values
     *                 <br>新的值
     * @return the API resource
     *         <br>API resource
     */
    @PutMapping("/api-resources/{code}")
    public ApiResourceView updateApiResource(@PathVariable String code, @RequestBody ApiResourceRequest request) {
        return scopes.updateApiResource(code, request);
    }

    /**
     * Deletes an API resource.
     * <p>
     * 刪除 API resource。
     *
     * @param code  the API resource code
     *              <br>API resource 代碼
     */
    @DeleteMapping("/api-resources/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteApiResource(@PathVariable String code) {
        scopes.deleteApiResource(code);
    }
}
