package jacky917.demo.resourceserver.clip;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Demo 資料初始化器。
 * 啟動時若資料不存在，建立最小化 Clip 測試資料。
 */
@Component
public class ClipDemoDataInitializer implements ApplicationRunner {

    private final ClipRepository clipRepository;

    public ClipDemoDataInitializer(ClipRepository clipRepository) {
        this.clipRepository = clipRepository;
    }

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

