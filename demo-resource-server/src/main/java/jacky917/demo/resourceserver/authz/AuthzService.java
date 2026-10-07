package jacky917.demo.resourceserver.authz;

import org.springframework.security.core.Authentication;

/**
 * Extension point for attribute-based access control (ABAC) on individual
 * resources.
 * <p>
 * 針對個別資源進行屬性型存取控制（ABAC）的擴充點。
 * <p>
 * The bean named {@code authzService} is called from SpEL, for example
 * {@code @PreAuthorize("@authzService.canAccessClip(authentication, #clipId)")}.
 * <p>
 * 名為 {@code authzService} 的 bean 會在 SpEL 中被呼叫，例如
 * {@code @PreAuthorize("@authzService.canAccessClip(authentication, #clipId)")}。
 */
public interface AuthzService {

    /**
     * Returns whether the caller may access the given clip.
     * <p>
     * 回傳呼叫端是否可以存取指定的 clip。
     *
     * @param authentication  the current authentication; may be {@code null}
     *                        <br>目前的驗證資訊，可為 {@code null}
     * @param clipId          the ID of the clip to access; may be {@code null}
     *                        <br>要存取的 clip ID，可為 {@code null}
     * @return {@code true} if access is allowed; {@code false} otherwise,
     *         including when either argument is {@code null}
     *         <br>允許存取時為 {@code true}；否則為 {@code false}，包含任一參數為
     *         {@code null} 的情況
     */
    boolean canAccessClip(Authentication authentication, String clipId);
}

