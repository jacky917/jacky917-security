package jacky917.security.autoconfigure.methodsecurity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

class Jacky917AuthorityEvaluatorTest {

    private final Jacky917AuthorityEvaluator evaluator = new Jacky917AuthorityEvaluator();
    private final Authentication auth = new TestingAuthenticationToken("alice", "n/a", "ROLE_A", "PERM_bb");

    @Test
    @DisplayName("hasAllAuthorities: 全部具備才通過")
    void hasAllRequiresEveryAuthority() {
        assertThat(evaluator.hasAllAuthorities(auth, "ROLE_A|PERM_bb")).isTrue();
        assertThat(evaluator.hasAllAuthorities(auth, " ROLE_A | | PERM_bb ")).isTrue();
        assertThat(evaluator.hasAllAuthorities(auth, "ROLE_A|PERM_cc")).isFalse();
    }

    @Test
    @DisplayName("hasAnyAuthority: 任一具備即通過")
    void hasAnyRequiresOneAuthority() {
        assertThat(evaluator.hasAnyAuthority(auth, "ROLE_X|PERM_bb")).isTrue();
        assertThat(evaluator.hasAnyAuthority(auth, "ROLE_X|PERM_cc")).isFalse();
    }

    @Test
    @DisplayName("只有分隔符或空白時一律拒絕（不可 fail-open）")
    void onlyDelimitersOrBlankShouldDeny() {
        for (String value : new String[]{"|", " | | ", "", "   ", null}) {
            assertThat(evaluator.hasAllAuthorities(auth, value)).as("all: [%s]", value).isFalse();
            assertThat(evaluator.hasAnyAuthority(auth, value)).as("any: [%s]", value).isFalse();
        }
    }

    @Test
    @DisplayName("authentication 為 null 時一律拒絕")
    void nullAuthenticationShouldDeny() {
        assertThat(evaluator.hasAllAuthorities(null, "ROLE_A")).isFalse();
        assertThat(evaluator.hasAnyAuthority(null, "ROLE_A")).isFalse();
    }
}
