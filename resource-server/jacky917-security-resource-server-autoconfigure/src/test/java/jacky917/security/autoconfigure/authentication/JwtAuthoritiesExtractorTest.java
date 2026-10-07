package jacky917.security.autoconfigure.authentication;

import jacky917.security.autoconfigure.properties.Jacky917SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthoritiesExtractorTest {

    private Jacky917SecurityProperties properties;
    private JwtAuthoritiesExtractor extractor;

    @BeforeEach
    void setUp() {
        properties = new Jacky917SecurityProperties();
        extractor = new JwtAuthoritiesExtractor(properties);
    }

    private Jwt createJwt(Map<String, Object> claims) {
        // Add required claims if they are missing for a valid Jwt object
        Map<String, Object> finalClaims = new HashMap<>(claims);
        finalClaims.putIfAbsent("sub", "test-subject");
        finalClaims.putIfAbsent("iat", Instant.now().getEpochSecond());
        return new Jwt("token-value", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "none"), finalClaims);
    }

    @Test
    @DisplayName("從 roles (List) 提取權限")
    void extractFromRolesList() {
        Jwt jwt = createJwt(Map.of("roles", List.of("ADMIN", "USER")));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    @DisplayName("從 roles (逗號分隔字串) 提取權限")
    void extractFromRolesString() {
        Jwt jwt = createJwt(Map.of("roles", "ADMIN, USER, DEV"));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("ROLE_ADMIN", "ROLE_DEV", "ROLE_USER");
    }

    @Test
    @DisplayName("從 permissions (List) 提取權限")
    void extractFromPermissionsList() {
        Jwt jwt = createJwt(Map.of("permissions", List.of("product:read", "product:write")));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("PERM_product:read", "PERM_product:write");
    }

    @Test
    @DisplayName("從 permissions (逗號分隔字串) 提取權限並去除空白")
    void extractFromPermissionsString() {
        Jwt jwt = createJwt(Map.of("permissions", "product:read, product:write , order:create"));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities))
                .containsExactly("PERM_order:create", "PERM_product:read", "PERM_product:write");
    }
    
    @Test
    @DisplayName("從 scope (空白分隔字串) 提取權限")
    void extractFromScopeString() {
        Jwt jwt = createJwt(Map.of("scope", "openid profile email"));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("SCOPE_email", "SCOPE_openid", "SCOPE_profile");
    }

    @Test
    @DisplayName("從 scp (List) 提取權限")
    void extractFromScpList() {
        Jwt jwt = createJwt(Map.of("scp", List.of("report:generate", "data:read")));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("SCOPE_data:read", "SCOPE_report:generate");
    }

    @Test
    @DisplayName("合併所有 claims 來源並去重排序")
    void extractFromAllSourcesAndDeDuplicate() {
        Jwt jwt = createJwt(Map.of(
                "roles", List.of("USER", "ADMIN"),
                "permissions", "product:read, user:manage, product:read", // 包含重複權限
                "scope", "openid profile",
                "scp", List.of("profile", "email:read") // "profile" 與 scope 重複, "email:read" 是新的
        ));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        // 權限應被排序且唯一
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly(
                "PERM_product:read",
                "PERM_user:manage",
                "ROLE_ADMIN",
                "ROLE_USER",
                "SCOPE_email:read",
                "SCOPE_openid",
                "SCOPE_profile"
        );
    }

    @Test
    @DisplayName("使用自訂 claim 名稱")
    void useCustomClaimNames() {
        properties.getJwt().getClaims().setRoles("my_roles");
        properties.getJwt().getClaims().setPermissions("perms");
        extractor = new JwtAuthoritiesExtractor(properties);

        Jwt jwt = createJwt(Map.of("my_roles", List.of("VIEWER"), "perms", "data:view"));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("PERM_data:view", "ROLE_VIEWER");
    }

    @Test
    @DisplayName("使用自訂權限前綴")
    void useCustomPrefixes() {
        properties.getJwt().getPrefix().setRole("R_");
        properties.getJwt().getPrefix().setPermission("P_");
        properties.getJwt().getPrefix().setScope("S_");
        extractor = new JwtAuthoritiesExtractor(properties);

        Jwt jwt = createJwt(Map.of(
                "roles", List.of("MANAGER"),
                "permissions", "order:create",
                "scope", "full_access"
        ));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("P_order:create", "R_MANAGER", "S_full_access");
    }
    
    @Test
    @DisplayName("當 claim 為空或不存在時，返回空集合")
    void handleEmptyOrMissingClaims() {
        Jwt jwt = createJwt(Map.of("roles", List.of(), "permissions", ""));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(authorities).isEmpty();

        Jwt jwt2 = createJwt(Map.of());
        Collection<GrantedAuthority> authorities2 = extractor.convert(jwt2);
        assertThat(authorities2).isEmpty();
    }

    @Test
    @DisplayName("當 claim 格式不支援時，應忽略並記錄警告")
    void handleUnsupportedClaimType() {
        Jwt jwt = createJwt(Map.of("roles", Map.of("key", "value"))); // 不支援 Map
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(authorities).isEmpty();
    }

    @Test
    @DisplayName("當 scope 為陣列時也應可解析為 SCOPE_ 權限")
    void handleScopeAsList() {
        Jwt jwt = createJwt(Map.of("scope", List.of("read", "write")));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("SCOPE_read", "SCOPE_write");
    }

    @Test
    @DisplayName("prefix 為 null 時視為空字串，不可產生 \"null\" 前綴")
    void nullPrefixShouldBeTreatedAsEmpty() {
        properties.getJwt().getPrefix().setRole(null);
        Jwt jwt = createJwt(Map.of("roles", List.of("ADMIN")));
        Collection<GrantedAuthority> authorities = extractor.convert(jwt);
        assertThat(getAuthoritiesAsStrings(authorities)).containsExactly("ADMIN");
    }

    private List<String> getAuthoritiesAsStrings(Collection<GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }
}
