package jacky917.demo.resourceserver.authz;

import jacky917.demo.resourceserver.clip.Clip;
import jacky917.demo.resourceserver.clip.ClipRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

/**
 * Demo ABAC 設定。
 * - 內建預設拒絕實作
 * - Demo 規則：依 clip.ownerId 與 JWT sub（authentication name）比對
 */
@Configuration
public class DemoAuthzConfiguration {

    @Bean
    public DenyAllAuthzService defaultDenyAllAuthzService() {
        return new DenyAllAuthzService();
    }

    @Bean("authzService")
    public AuthzService authzService(DenyAllAuthzService denyAll, ClipRepository clipRepository) {
        return new AuthzService() {
            @Override
            public boolean canAccessClip(Authentication authentication, String clipId) {
                if (authentication == null || !StringUtils.hasText(clipId)) {
                    return false;
                }
                return clipRepository.findById(clipId)
                        .map(Clip::getOwnerId)
                        .map(ownerId -> ownerId.equals(authentication.getName()))
                        .orElseGet(() -> denyAll.canAccessClip(authentication, clipId));
            }
        };
    }
}

