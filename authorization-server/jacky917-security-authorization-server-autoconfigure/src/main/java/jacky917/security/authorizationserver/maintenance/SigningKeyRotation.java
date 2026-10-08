package jacky917.security.authorizationserver.maintenance;

import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyService;
import jacky917.security.authorizationserver.keys.SigningKeyStatus;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Rotates the signing key (detailed design §5.7).
 * <p>
 * 輪換簽章金鑰（詳細設計 §5.7）。
 * <ol>
 *   <li>When the active key is {@code rotationPeriod - announcePeriod} old,
 *       a {@code NEXT} key is created; its public key is published at
 *       once.
 *       <br>目前的金鑰使用滿 {@code rotationPeriod - announcePeriod} 時建立
 *       {@code NEXT} 金鑰，其公鑰立即公開。</li>
 *   <li>When the {@code NEXT} key has been published for
 *       {@code announcePeriod}, it becomes {@code ACTIVE} and the old key
 *       becomes {@code RETIRING}, still published.
 *       <br>{@code NEXT} 金鑰公開滿 {@code announcePeriod} 後成為
 *       {@code ACTIVE}，舊金鑰改為 {@code RETIRING}，仍然公開。</li>
 *   <li>A {@code RETIRING} key is {@code RETIRED}, no longer published, when
 *       every token it signed has expired and resource servers have
 *       refreshed their JWKS cache.
 *       <br>{@code RETIRING} 金鑰簽發的 token 全部到期、且 Resource Server 已
 *       更新 JWKS 快取後，改為 {@code RETIRED}，不再公開。</li>
 * </ol>
 * Each step checks the current status, so running it again, or on several
 * instances, does nothing extra.
 * <p>
 * 每一步都先檢查目前的狀態，重複執行或在多個實例上執行都不會多做事。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class SigningKeyRotation {

    /**
     * How long resource servers cache the JWKS: Spring Security's default.
     * <p>
     * Resource Server 快取 JWKS 的時間：Spring Security 的預設值。
     */
    public static final Duration JWKS_CACHE_TTL = Duration.ofMinutes(5);

    /**
     * Lifetime of ID tokens issued by Spring Authorization Server.
     * <p>
     * Spring Authorization Server 簽發之 ID Token 的有效期。
     */
    public static final Duration ID_TOKEN_TTL = Duration.ofMinutes(30);

    private final SigningKeyStore store;
    private final SigningKeyService keys;
    private final TransactionOperations transactions;
    private final Duration rotationPeriod;
    private final Duration announcePeriod;
    private final Duration retireAfter;
    private final Clock clock;

    /**
     * Creates the rotation.
     * <p>
     * 建立輪換。
     *
     * @param store             the key store
     *                          <br>金鑰儲存
     * @param keys              generates keys and caches the active one
     *                          <br>產生金鑰並快取目前的金鑰
     * @param transactions      swaps the active key in one transaction
     *                          <br>在同一個交易中替換目前的金鑰
     * @param rotationPeriod    how long a key signs tokens
     *                          <br>一把金鑰簽章的時間
     * @param announcePeriod    how long a new key is published before it
     *                          signs
     *                          <br>新金鑰在簽章前公開的時間
     * @param accessTokenTtl    the access token lifetime
     *                          <br>Access Token 有效期
     * @param clock             the clock
     *                          <br>時鐘
     */
    public SigningKeyRotation(SigningKeyStore store, SigningKeyService keys, TransactionOperations transactions,
                              Duration rotationPeriod, Duration announcePeriod, Duration accessTokenTtl, Clock clock) {
        this.store = store;
        this.keys = keys;
        this.transactions = transactions;
        this.rotationPeriod = rotationPeriod;
        this.announcePeriod = announcePeriod;
        Duration longestToken = accessTokenTtl.compareTo(ID_TOKEN_TTL) > 0 ? accessTokenTtl : ID_TOKEN_TTL;
        this.retireAfter = longestToken.plus(JWKS_CACHE_TTL);
        this.clock = clock;
    }

    /**
     * Runs the steps that are due.
     * <p>
     * 執行已到期的步驟。
     */
    public void rotate() {
        Instant now = clock.instant();
        boolean changed = false;
        Optional<SigningKey> active = store.findActive();
        if (active.isEmpty()) {
            // 正常情況下啟動時已建立；例如金鑰被手動刪除時補上
            keys.ensureActiveKey();
            return;
        }
        List<SigningKey> next = store.findByStatus(SigningKeyStatus.NEXT);
        Instant activatedAt = active.get().activatedAt() == null ? active.get().createdAt() : active.get().activatedAt();
        if (next.isEmpty() && !now.isBefore(activatedAt.plus(rotationPeriod).minus(announcePeriod))) {
            SigningKey created = keys.generate(SigningKeyStatus.NEXT);
            store.save(created);
            log.info("Published the next signing key {}; it starts signing in {}", created.kid(), announcePeriod);
            changed = true;
        } else if (!next.isEmpty() && !now.isBefore(next.get(0).createdAt().plus(announcePeriod))) {
            SigningKey promoted = next.get(0);
            Boolean swapped = transactions.execute(status -> {
                // 唯一索引只允許一把 ACTIVE：先改舊的，再改新的；任一步被其他實例搶先就整個回滾
                if (!store.transition(active.get().kid(), SigningKeyStatus.ACTIVE, SigningKeyStatus.RETIRING, now)
                        || !store.transition(promoted.kid(), SigningKeyStatus.NEXT, SigningKeyStatus.ACTIVE, now)) {
                    status.setRollbackOnly();
                    return false;
                }
                return true;
            });
            if (Boolean.TRUE.equals(swapped)) {
                log.info("Signing key {} is now active; {} is retiring", promoted.kid(), active.get().kid());
                changed = true;
            }
        }
        for (SigningKey retiring : store.findByStatus(SigningKeyStatus.RETIRING)) {
            if (retiring.retiringAt() != null && !now.isBefore(retiring.retiringAt().plus(retireAfter))
                    && store.transition(retiring.kid(), SigningKeyStatus.RETIRING, SigningKeyStatus.RETIRED, now)) {
                log.info("Retired signing key {}; it is no longer published", retiring.kid());
                changed = true;
            }
        }
        if (changed) {
            keys.evictCache();
        }
    }
}
