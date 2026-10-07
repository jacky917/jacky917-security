package jacky917.demo.resourceserver.controller;

import io.swagger.v3.oas.annotations.Operation;
import jacky917.security.annotations.RequireAll;
import jacky917.security.annotations.RequireAny;
import jacky917.security.annotations.RequirePerm;
import jacky917.security.annotations.RequireRole;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Demo endpoints for each access rule: public, authenticated, role,
 * permission, AND, OR, and ABAC.
 * <p>
 * 示範各種存取規則的端點：公開、需驗證、角色、權限、AND、OR 與 ABAC。
 */
@RestController
@RequestMapping
public class DemoSecureController {

    /**
     * Returns a fixed pong response; no token is required.
     * <p>
     * 回傳固定的 pong 回應，不需要 token。
     *
     * @return a body with {@code ok} and {@code message}
     *         <br>包含 {@code ok} 與 {@code message} 的回應內容
     */
    @Operation(summary = "公開健康檢查", description = "不需 JWT 即可存取，用於驗證服務可用性。")
    @GetMapping("/public/ping")
    public Map<String, Object> ping() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("message", "pong");
        return body;
    }

    /**
     * Returns the caller's name and authorities.
     * <p>
     * 回傳呼叫端的名稱與 authority 清單。
     *
     * @param authentication  the current authentication
     *                        <br>目前的驗證資訊
     * @return a body with {@code name} and the sorted {@code authorities}
     *         <br>包含 {@code name} 與已排序 {@code authorities} 的回應內容
     */
    @Operation(summary = "取得當前使用者資訊", description = "需要有效 JWT，回傳使用者名稱與 authority 清單。")
    @GetMapping("/secure/me")
    public Map<String, Object> me(Authentication authentication) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", authentication.getName());
        body.put("authorities", authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .collect(Collectors.toList()));
        return body;
    }

    /**
     * Demonstrates {@code @RequireRole}; requires {@code ROLE_A}.
     * <p>
     * 示範 {@code @RequireRole}，需要 {@code ROLE_A}。
     *
     * @return a body that reports the request was allowed
     *         <br>表示請求已被允許的回應內容
     */
    @RequireRole("A")
    @Operation(summary = "角色授權範例", description = "需具備 ROLE_A。")
    @GetMapping("/secure/role-a")
    public Map<String, Object> roleA() {
        return Map.of("path", "/secure/role-a", "result", "allowed");
    }

    /**
     * Demonstrates {@code @RequirePerm}; requires {@code PERM_bb}.
     * <p>
     * 示範 {@code @RequirePerm}，需要 {@code PERM_bb}。
     *
     * @return a body that reports the request was allowed
     *         <br>表示請求已被允許的回應內容
     */
    @RequirePerm("bb")
    @Operation(summary = "權限授權範例", description = "需具備 PERM_bb。")
    @GetMapping("/secure/perm-bb")
    public Map<String, Object> permBb() {
        return Map.of("path", "/secure/perm-bb", "result", "allowed");
    }

    /**
     * Demonstrates {@code @RequireAll}; requires both {@code ROLE_A} and
     * {@code PERM_bb}.
     * <p>
     * 示範 {@code @RequireAll}，需要同時具備 {@code ROLE_A} 與 {@code PERM_bb}。
     *
     * @return a body that reports the request was allowed
     *         <br>表示請求已被允許的回應內容
     */
    @RequireAll("ROLE_A|PERM_bb")
    @Operation(summary = "AND 授權範例", description = "需同時具備 ROLE_A 與 PERM_bb。")
    @GetMapping("/secure/and")
    public Map<String, Object> andRule() {
        return Map.of("path", "/secure/and", "result", "allowed");
    }

    /**
     * Demonstrates {@code @RequireAny}; requires {@code ROLE_A} or
     * {@code PERM_bb}.
     * <p>
     * 示範 {@code @RequireAny}，需要 {@code ROLE_A} 或 {@code PERM_bb} 其中之一。
     *
     * @return a body that reports the request was allowed
     *         <br>表示請求已被允許的回應內容
     */
    @RequireAny("ROLE_A|PERM_bb")
    @Operation(summary = "OR 授權範例", description = "具備 ROLE_A 或 PERM_bb 任一即可。")
    @GetMapping("/secure/or")
    public Map<String, Object> orRule() {
        return Map.of("path", "/secure/or", "result", "allowed");
    }

    /**
     * Demonstrates ABAC; requires {@code PERM_clip:read}, and the clip's owner
     * must be the caller.
     * <p>
     * 示範 ABAC，需要 {@code PERM_clip:read}，且 clip 的擁有者必須是呼叫端。
     *
     * @param clipId  the ID of the clip to access
     *                <br>要存取的 clip ID
     * @return a body that reports the request was allowed
     *         <br>表示請求已被允許的回應內容
     */
    @PreAuthorize("hasAuthority('PERM_clip:read') and @authzService.canAccessClip(authentication, #clipId)")
    @Operation(summary = "ABAC 授權範例", description = "需具備 PERM_clip:read，且資料庫中 clip.ownerId 必須等於 JWT 的 sub。")
    @GetMapping("/secure/abac/{clipId}")
    public Map<String, Object> abac(@PathVariable String clipId) {
        return Map.of("path", "/secure/abac/" + clipId, "result", "allowed");
    }
}

