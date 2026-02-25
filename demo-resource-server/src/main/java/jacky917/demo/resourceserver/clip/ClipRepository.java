package jacky917.demo.resourceserver.clip;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Clip 資料存取介面。
 */
public interface ClipRepository extends JpaRepository<Clip, String> {
}

