package jacky917.security.resourceserver.autoconfigure.methodsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Authority checks used by the {@code @RequireAny} and {@code @RequireAll}
 * method security annotations.
 * <p>
 * 提供 {@code @RequireAny} 與 {@code @RequireAll} 方法級授權註解使用的
 * authority 判斷工具。
 * <p>
 * Both methods fail closed: they return {@code false} when the
 * authentication is {@code null} or when no non-blank authority is listed.
 * Instances are stateless and thread-safe.
 * <p>
 * 兩個方法皆採「預設拒絕」：當驗證資訊為 {@code null}，或沒有列出任何非空白
 * 的 authority 時，一律回傳 {@code false}。實例為無狀態且執行緒安全。
 *
 * @since 0.0.1
 */
public class Jacky917AuthorityEvaluator {

    /**
     * Creates a new evaluator.
     * <p>
     * 建立新的判斷工具實例。
     */
    public Jacky917AuthorityEvaluator() {
    }

    /**
     * Returns whether the authentication holds at least one of the listed
     * authorities (logical OR).
     * <p>
     * 回傳驗證資訊是否至少具備其中一個列出的 authority（OR 條件）。
     *
     * @param authentication       the current authentication; may be
     *                             {@code null}
     *                             <br>目前的驗證資訊，可為 {@code null}
     * @param requiredAuthorities  full authority names separated by
     *                             {@code |}; blank entries are ignored
     *                             <br>以 {@code |} 分隔的完整 authority
     *                             名稱，空白項目會被忽略
     * @return {@code true} if any listed authority is held; {@code false} if
     *         none is held, {@code authentication} is {@code null}, or no
     *         non-blank authority is listed
     *         <br>具備任一列出的 authority 時為 {@code true}；全部不具備、
     *         {@code authentication} 為 {@code null}，或未列出任何非空白
     *         authority 時為 {@code false}
     */
    public boolean hasAnyAuthority(Authentication authentication, String requiredAuthorities) {
        List<String> required = parseRequiredAuthorities(requiredAuthorities);
        if (authentication == null || required.isEmpty()) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return required.stream().anyMatch(owned::contains);
    }

    /**
     * Returns whether the authentication holds every listed authority
     * (logical AND).
     * <p>
     * 回傳驗證資訊是否具備所有列出的 authority（AND 條件）。
     *
     * @param authentication       the current authentication; may be
     *                             {@code null}
     *                             <br>目前的驗證資訊，可為 {@code null}
     * @param requiredAuthorities  full authority names separated by
     *                             {@code |}; blank entries are ignored
     *                             <br>以 {@code |} 分隔的完整 authority
     *                             名稱，空白項目會被忽略
     * @return {@code true} if every listed authority is held; {@code false}
     *         if any is missing, {@code authentication} is {@code null}, or
     *         no non-blank authority is listed
     *         <br>具備所有列出的 authority 時為 {@code true}；缺少任一項、
     *         {@code authentication} 為 {@code null}，或未列出任何非空白
     *         authority 時為 {@code false}
     */
    public boolean hasAllAuthorities(Authentication authentication, String requiredAuthorities) {
        List<String> required = parseRequiredAuthorities(requiredAuthorities);
        // An empty list must not pass: allMatch() on an empty stream is true.
        if (authentication == null || required.isEmpty()) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return owned.containsAll(required);
    }

    private Set<String> currentAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    private List<String> parseRequiredAuthorities(String requiredAuthorities) {
        if (!StringUtils.hasText(requiredAuthorities)) {
            return List.of();
        }
        return Stream.of(requiredAuthorities.split("\\|"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }
}
