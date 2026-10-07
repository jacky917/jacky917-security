package jacky917.demo.resourceserver.clip;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Startup runner that inserts the demo clips if they are missing.
 * <p>
 * 啟動時若 demo clip 不存在則建立資料的初始化器。
 * <p>
 * It creates {@code demo-001} owned by {@code alice} and
 * {@code private-001} owned by {@code bob}.
 * <p>
 * 會建立擁有者為 {@code alice} 的 {@code demo-001}，以及擁有者為
 * {@code bob} 的 {@code private-001}。
 */
@Component
public class ClipDemoDataInitializer implements ApplicationRunner {

    private final ClipRepository clipRepository;

    /**
     * Creates an initializer that writes through the given repository.
     * <p>
     * 建立透過指定 repository 寫入資料的初始化器。
     *
     * @param clipRepository  the repository used to save clips
     *                        <br>用來儲存 clip 的 repository
     */
    public ClipDemoDataInitializer(ClipRepository clipRepository) {
        this.clipRepository = clipRepository;
    }

    /**
     * Inserts each demo clip that does not exist yet; existing rows are left
     * unchanged.
     * <p>
     * 建立尚未存在的 demo clip；已存在的資料不會變動。
     *
     * @param args  the application arguments; ignored
     *              <br>應用程式參數，不使用
     */
    @Override
    public void run(ApplicationArguments args) {
        if (!clipRepository.existsById("demo-001")) {
            clipRepository.save(new Clip("demo-001", "Demo Clip", "alice"));
        }
        if (!clipRepository.existsById("private-001")) {
            clipRepository.save(new Clip("private-001", "Private Clip", "bob"));
        }
    }
}

