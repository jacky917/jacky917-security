package jacky917.demo.resourceserver.authz;

import org.springframework.security.core.Authentication;

/**
 * {@link AuthzService} implementation that denies every request.
 * <p>
 * 一律拒絕存取的 {@code AuthzService} 實作。
 * <p>
 * Use it as a safe default; real applications replace it with their own
 * rules.
 * <p>
 * 作為安全的預設值使用；實際專案應以自己的規則取代。
 */
public class DenyAllAuthzService implements AuthzService {

    /**
     * Always denies access.
     * <p>
     * 一律拒絕存取。
     *
     * @param authentication  ignored
     *                        <br>不使用
     * @param clipId          ignored
     *                        <br>不使用
     * @return always {@code false}
     *         <br>固定為 {@code false}
     */
    @Override
    public boolean canAccessClip(Authentication authentication, String clipId) {
        return false;
    }
}

