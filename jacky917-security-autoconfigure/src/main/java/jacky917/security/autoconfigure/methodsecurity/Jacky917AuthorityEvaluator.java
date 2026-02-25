package jacky917.security.autoconfigure.methodsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 提供方法級授權註解使用的 authority 判斷工具。
 */
public class Jacky917AuthorityEvaluator {

    /**
     * OR 判斷：任一 authority 符合即回傳 true。
     */
    public boolean hasAnyAuthority(Authentication authentication, String requiredAuthorities) {
        if (authentication == null || !StringUtils.hasText(requiredAuthorities)) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return parseRequiredAuthorities(requiredAuthorities)
                .filter(StringUtils::hasText)
                .anyMatch(owned::contains);
    }

    /**
     * AND 判斷：全部 authority 符合才回傳 true。
     */
    public boolean hasAllAuthorities(Authentication authentication, String requiredAuthorities) {
        if (authentication == null || !StringUtils.hasText(requiredAuthorities)) {
            return false;
        }
        Set<String> owned = currentAuthorities(authentication);
        return parseRequiredAuthorities(requiredAuthorities)
                .filter(StringUtils::hasText)
                .allMatch(owned::contains);
    }

    private Set<String> currentAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    private Stream<String> parseRequiredAuthorities(String requiredAuthorities) {
        return Stream.of(requiredAuthorities.split("\\|"))
                .map(String::trim)
                .filter(StringUtils::hasText);
    }
}

