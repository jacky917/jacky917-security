package jacky917.demo.resourceserver.authz;

import jacky917.demo.resourceserver.clip.Clip;
import jacky917.demo.resourceserver.clip.ClipRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

/**
 * Demo ABAC configuration.
 * <p>
 * Demo ABAC 設定。
 * <p>
 * Access to a clip is allowed only when its {@code ownerId} equals the
 * authentication name (the JWT {@code sub}). Unknown clips fall back to
 * {@link DenyAllAuthzService}, so they are always denied.
 * <p>
 * 只有當 clip 的 {@code ownerId} 等於驗證名稱（JWT 的 {@code sub}）時才允許
 * 存取。找不到的 clip 會交由 {@code DenyAllAuthzService} 處理，因此一律拒絕。
 */
@Configuration
public class DemoAuthzConfiguration {

    /**
     * Creates the fallback service that denies every request.
     * <p>
     * 建立一律拒絕的後備服務。
     *
     * @return a new deny-all service
     *         <br>新的一律拒絕服務
     */
    @Bean
    public DenyAllAuthzService defaultDenyAllAuthzService() {
        return new DenyAllAuthzService();
    }

    /**
     * Creates the {@code authzService} bean that compares the clip owner with
     * the caller.
     * <p>
     * 建立 {@code authzService} bean，比對 clip 擁有者與呼叫端。
     *
     * @param denyAll         the fallback used when the clip does not exist
     *                        <br>clip 不存在時使用的後備服務
     * @param clipRepository  the repository used to look up clips
     *                        <br>用來查詢 clip 的 repository
     * @return the owner-based ABAC service
     *         <br>以擁有者判斷的 ABAC 服務
     */
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

