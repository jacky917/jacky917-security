package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserAuthorities;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link PrincipalNormalizer}（D16）：轉為 UsernamePasswordAuthenticationToken + User(使用者 ID)，並保證有
 * factor authority（Spring Security 以它決定 ID Token 的 auth_time）。
 */
@DisplayName("PrincipalNormalizer")
class PrincipalNormalizerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private final UserAccountService users = mock(UserAccountService.class);
    private final PrincipalNormalizer normalizer = new PrincipalNormalizer(users, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    @DisplayName("principal 為 User(使用者 ID)，authority 為 ROLE_／PERM_，沒有密碼")
    void standardPrincipal() {
        when(users.loadAuthorities("user-1")).thenReturn(new UserAuthorities(Set.of("USER"), Set.of("order:read")));
        Authentication normalized = normalizer.normalize("user-1", new TestingAuthenticationToken("google-sub", null));
        assertThat(normalized).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(normalized.getName()).isEqualTo("user-1");
        assertThat(normalized.isAuthenticated()).isTrue();
        assertThat(((User) normalized.getPrincipal()).getPassword()).isNull();
        assertThat(names(normalized.getAuthorities())).contains("ROLE_USER", "PERM_order:read")
                .doesNotContain("google-sub");
    }

    @Test
    @DisplayName("原登入沒有 factor authority（oauth2Login）：加入帶登入時間的 FACTOR_AUTHORIZATION_CODE")
    void addsFactorWhenMissing() {
        when(users.loadAuthorities("user-1")).thenReturn(new UserAuthorities(Set.of(), Set.of()));
        Authentication normalized = normalizer.normalize("user-1",
                new TestingAuthenticationToken("x", null, List.of(new SimpleGrantedAuthority("SCOPE_openid"))));
        assertThat(normalized.getAuthorities()).filteredOn(FactorGrantedAuthority.class::isInstance)
                .singleElement().satisfies(authority -> {
                    assertThat(authority.getAuthority()).isEqualTo(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY);
                    assertThat(((FactorGrantedAuthority) authority).getIssuedAt()).isEqualTo(NOW);
                });
        assertThat(names(normalized.getAuthorities())).doesNotContain("SCOPE_openid");
    }

    @Test
    @DisplayName("原登入已有 factor authority：保留原本的，不另外加入")
    void keepsExistingFactors() {
        when(users.loadAuthorities("user-1")).thenReturn(new UserAuthorities(Set.of(), Set.of()));
        Instant loggedInAt = NOW.minusSeconds(30);
        FactorGrantedAuthority password = FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(loggedInAt).build();
        Authentication normalized = normalizer.normalize("user-1", new TestingAuthenticationToken("x", null, List.of(password)));
        List<GrantedAuthority> factors = normalized.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance).map(GrantedAuthority.class::cast).toList();
        assertThat(factors).containsExactly(password);
    }

    private static List<String> names(java.util.Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
