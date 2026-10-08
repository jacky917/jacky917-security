package jacky917.security.authorizationserver.federation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.util.SerializationUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link LinkIntent}：存放在瀏覽器 Session 中，必須能序列化（Spring Session JDBC 會把 Session 屬性存進資料庫）；
 * 只能屬於發出請求的使用者；10 分鐘後失效。
 */
@DisplayName("LinkIntent")
class LinkIntentTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    @Test
    @DisplayName("含實際登入（密碼 factor）的請求可以序列化並還原")
    void survivesSerialization() {
        Authentication login = UsernamePasswordAuthenticationToken.authenticated("user-1", null,
                List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(NOW)
                        .build()));
        LinkIntent intent = new LinkIntent("user-1", "google", login, NOW);
        byte[] bytes = SerializationUtils.serialize(intent);
        @SuppressWarnings("deprecation")
        LinkIntent restored = (LinkIntent) SerializationUtils.deserialize(bytes);
        assertThat(restored).isEqualTo(intent);
        assertThat(restored.previous().getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("使用者 ID 與登入不一致：拒絕建立")
    void belongsToTheLoggedInUser() {
        Authentication login = UsernamePasswordAuthenticationToken.authenticated("user-1", null, List.of());
        assertThatThrownBy(() -> new LinkIntent("user-2", "google", login, NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("建立後 10 分鐘內有效")
    void expiresAfterTenMinutes() {
        LinkIntent intent = new LinkIntent("user-1", "google",
                UsernamePasswordAuthenticationToken.authenticated("user-1", null, List.of()), NOW);
        assertThat(intent.isFresh(NOW.plus(Duration.ofMinutes(10)).minusMillis(1))).isTrue();
        assertThat(intent.isFresh(NOW.plus(Duration.ofMinutes(10)))).isFalse();
    }
}
