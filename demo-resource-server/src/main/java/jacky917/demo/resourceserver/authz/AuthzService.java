package jacky917.demo.resourceserver.authz;

import org.springframework.security.core.Authentication;

/**
 * ABAC hook 介面：提供資源屬性層級的授權判斷擴充點。
 */
public interface AuthzService {

    /**
     * 判斷是否允許存取特定 clip。
     *
     * @param authentication 當前驗證資訊
     * @param clipId         資源識別
     * @return 允許回傳 true，否則 false
     */
    boolean canAccessClip(Authentication authentication, String clipId);
}

