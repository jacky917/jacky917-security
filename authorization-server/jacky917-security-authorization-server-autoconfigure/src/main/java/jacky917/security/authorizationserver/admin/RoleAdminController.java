package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.admin.RoleAdminService.PermissionRequest;
import jacky917.security.authorizationserver.admin.RoleAdminService.PermissionView;
import jacky917.security.authorizationserver.admin.RoleAdminService.RoleRequest;
import jacky917.security.authorizationserver.admin.RoleAdminService.RoleView;
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
 * Roles and permissions in the administration API (phase 3 and 4 design
 * §4.2).
 * <p>
 * 管理 API 中的角色與權限（第 3、4 階段設計 §4.2）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api")
public class RoleAdminController {

    private final RoleAdminService roles;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param roles  manages roles and permissions
     *               <br>管理角色與權限
     */
    public RoleAdminController(RoleAdminService roles) {
        this.roles = roles;
    }

    /**
     * Lists the roles.
     * <p>
     * 列出角色。
     *
     * @return the roles, by code
     *         <br>角色，依代碼排序
     */
    @GetMapping("/roles")
    public List<RoleView> roles() {
        return roles.roles();
    }

    /**
     * Creates a role.
     * <p>
     * 建立角色。
     *
     * @param request  the role
     *                 <br>角色
     * @return the created role
     *         <br>建立的角色
     */
    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public RoleView createRole(@RequestBody RoleRequest request) {
        return roles.createRole(request);
    }

    /**
     * Returns a role.
     * <p>
     * 回傳角色。
     *
     * @param code  the role code
     *              <br>角色代碼
     * @return the role
     *         <br>角色
     */
    @GetMapping("/roles/{code}")
    public RoleView role(@PathVariable String code) {
        return roles.role(code);
    }

    /**
     * Replaces the name, description and permissions of a role.
     * <p>
     * 取代角色的名稱、說明與權限。
     *
     * @param code     the role code
     *                 <br>角色代碼
     * @param request  the new values
     *                 <br>新的值
     * @return the updated role
     *         <br>更新後的角色
     */
    @PutMapping("/roles/{code}")
    public RoleView updateRole(@PathVariable String code, @RequestBody RoleRequest request) {
        return roles.updateRole(code, request);
    }

    /**
     * Deletes a role.
     * <p>
     * 刪除角色。
     *
     * @param code  the role code
     *              <br>角色代碼
     */
    @DeleteMapping("/roles/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteRole(@PathVariable String code) {
        roles.deleteRole(code);
    }

    /**
     * Lists the permissions.
     * <p>
     * 列出權限。
     *
     * @return the permissions, by code
     *         <br>權限，依代碼排序
     */
    @GetMapping("/permissions")
    public List<PermissionView> permissions() {
        return roles.permissions();
    }

    /**
     * Creates a permission.
     * <p>
     * 建立權限。
     *
     * @param request  the permission
     *                 <br>權限
     * @return the created permission
     *         <br>建立的權限
     */
    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    public PermissionView createPermission(@RequestBody PermissionRequest request) {
        return roles.createPermission(request);
    }

    /**
     * Returns a permission.
     * <p>
     * 回傳權限。
     *
     * @param code  the permission code
     *              <br>權限代碼
     * @return the permission
     *         <br>權限
     */
    @GetMapping("/permissions/{code}")
    public PermissionView permission(@PathVariable String code) {
        return roles.permission(code);
    }

    /**
     * Changes the name and description of a permission.
     * <p>
     * 變更權限的名稱與說明。
     *
     * @param code     the permission code
     *                 <br>權限代碼
     * @param request  the new values
     *                 <br>新的值
     * @return the updated permission
     *         <br>更新後的權限
     */
    @PutMapping("/permissions/{code}")
    public PermissionView updatePermission(@PathVariable String code, @RequestBody PermissionRequest request) {
        return roles.updatePermission(code, request);
    }

    /**
     * Deletes a permission.
     * <p>
     * 刪除權限。
     *
     * @param code  the permission code
     *              <br>權限代碼
     */
    @DeleteMapping("/permissions/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deletePermission(@PathVariable String code) {
        roles.deletePermission(code);
    }
}
