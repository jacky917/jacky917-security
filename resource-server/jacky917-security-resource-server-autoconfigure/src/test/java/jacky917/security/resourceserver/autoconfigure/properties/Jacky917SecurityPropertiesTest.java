package jacky917.security.resourceserver.autoconfigure.properties;

import jacky917.security.core.Jacky917AuthorityPrefix;
import jacky917.security.core.Jacky917ClaimNames;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 預設值以字串常值撰寫（configuration processor 無法解析其他模組的常數，改用常數會讓 IDE 看不到預設值），
 * 因此以本測試確保它們與 core 的 claim 契約一致。
 */
class Jacky917SecurityPropertiesTest {

    @Test
    @DisplayName("預設的 claim 名稱與前綴必須與 jacky917-security-core 一致")
    void defaultsMatchCoreContract() {
        Jacky917SecurityProperties.Jwt jwt = new Jacky917SecurityProperties().getJwt();

        assertThat(jwt.getClaims().getRoles()).isEqualTo(Jacky917ClaimNames.ROLES);
        assertThat(jwt.getClaims().getPermissions()).isEqualTo(Jacky917ClaimNames.PERMISSIONS);
        assertThat(jwt.getClaims().getScope()).isEqualTo(Jacky917ClaimNames.SCOPE);
        assertThat(jwt.getClaims().getScp()).isEqualTo(Jacky917ClaimNames.SCP);
        assertThat(jwt.getPrefix().getRole()).isEqualTo(Jacky917AuthorityPrefix.ROLE);
        assertThat(jwt.getPrefix().getPermission()).isEqualTo(Jacky917AuthorityPrefix.PERMISSION);
        assertThat(jwt.getPrefix().getScope()).isEqualTo(Jacky917AuthorityPrefix.SCOPE);
    }
}
