package jacky917.security.authorizationserver.refresh;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;

/**
 * Spring's refresh token provider, run through a
 * {@link RefreshTokenReuseDetector} (detailed design §5.4).
 * <p>
 * 經過 {@code RefreshTokenReuseDetector} 執行的 Spring 刷新 provider（詳細設計
 * §5.4）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ReuseDetectingRefreshTokenProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;
    private final RefreshTokenReuseDetector detector;

    /**
     * Wraps Spring's refresh provider.
     * <p>
     * 包裝 Spring 的刷新 provider。
     *
     * @param delegate  Spring's {@code OAuth2RefreshTokenAuthenticationProvider}
     *                  <br>Spring 的 {@code OAuth2RefreshTokenAuthenticationProvider}
     * @param detector  the reuse detector
     *                  <br>重用偵測器
     */
    public ReuseDetectingRefreshTokenProvider(AuthenticationProvider delegate, RefreshTokenReuseDetector detector) {
        this.delegate = delegate;
        this.detector = detector;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        return detector.authenticate((OAuth2RefreshTokenAuthenticationToken) authentication, delegate);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }
}
