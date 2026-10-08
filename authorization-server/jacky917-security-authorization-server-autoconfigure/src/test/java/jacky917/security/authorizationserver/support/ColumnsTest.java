package jacky917.security.authorizationserver.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Columns.truncate")
class ColumnsTest {

    @Test
    @DisplayName("null 與未超過長度的值原樣回傳；超過時截斷")
    void truncates() {
        assertThat(Columns.truncate(null, 3)).isNull();
        assertThat(Columns.truncate("abc", 3)).isEqualTo("abc");
        assertThat(Columns.truncate("abcd", 3)).isEqualTo("abc");
    }

    @Test
    @DisplayName("不把 emoji（代理對）切成一半，避免存入無效的字元")
    void neverSplitsSurrogatePairs() {
        String value = "ab😀c"; // ab😀c
        assertThat(Columns.truncate(value, 3)).isEqualTo("ab");
        assertThat(Columns.truncate(value, 4)).isEqualTo("ab😀");
    }
}
