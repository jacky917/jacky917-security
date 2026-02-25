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
 * Demo 端點：展示 permitAll、authenticated、RBAC、Permission、AND/OR 與 ABAC hook。
 */
@RestController
@RequestMapping
public class DemoSecureController {

    @Operation(summary = "公開健康檢查", description = "不需 JWT 即可存取，用於驗證服務可用性。")
    @GetMapping("/public/ping")
    public Map<String, Object> ping() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("message", "pong");
        return body;
    }

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

    @RequireRole("A")
    @Operation(summary = "角色授權範例", description = "需具備 ROLE_A。")
    @GetMapping("/secure/role-a")
    public Map<String, Object> roleA() {
        return Map.of("path", "/secure/role-a", "result", "allowed");
    }

    @RequirePerm("bb")
    @Operation(summary = "權限授權範例", description = "需具備 PERM_bb。")
    @GetMapping("/secure/perm-bb")
    public Map<String, Object> permBb() {
        return Map.of("path", "/secure/perm-bb", "result", "allowed");
    }

    @RequireAll("ROLE_A|PERM_bb")
    @Operation(summary = "AND 授權範例", description = "需同時具備 ROLE_A 與 PERM_bb。")
    @GetMapping("/secure/and")
    public Map<String, Object> andRule() {
        return Map.of("path", "/secure/and", "result", "allowed");
    }

    @RequireAny("ROLE_A|PERM_bb")
    @Operation(summary = "OR 授權範例", description = "具備 ROLE_A 或 PERM_bb 任一即可。")
    @GetMapping("/secure/or")
    public Map<String, Object> orRule() {
        return Map.of("path", "/secure/or", "result", "allowed");
    }

    @PreAuthorize("hasAuthority('PERM_clip:read') and @authzService.canAccessClip(authentication, #clipId)")
    @Operation(summary = "ABAC 授權範例", description = "需具備 PERM_clip:read，且資料庫中 clip.ownerId 必須等於 JWT 的 sub。")
    @GetMapping("/secure/abac/{clipId}")
    public Map<String, Object> abac(@PathVariable String clipId) {
        return Map.of("path", "/secure/abac/" + clipId, "result", "allowed");
    }
}

