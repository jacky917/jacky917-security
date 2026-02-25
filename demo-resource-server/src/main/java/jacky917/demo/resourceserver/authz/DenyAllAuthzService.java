package jacky917.demo.resourceserver.authz;

import org.springframework.security.core.Authentication;

/**
 * 預設 ABAC 實作：一律拒絕。
 * 真實專案可在應用層覆寫此實作。
 */
public class DenyAllAuthzService implements AuthzService {

    @Override
    public boolean canAccessClip(Authentication authentication, String clipId) {
        return false;
    }
}

