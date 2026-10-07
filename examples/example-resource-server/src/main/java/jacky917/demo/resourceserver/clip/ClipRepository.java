package jacky917.demo.resourceserver.clip;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data repository for {@link Clip} entities, keyed by clip ID.
 * <p>
 * {@code Clip} 實體的 Spring Data repository，以 clip ID 為主鍵。
 */
public interface ClipRepository extends JpaRepository<Clip, String> {
}

