package jacky917.demo.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the example backend-for-frontend on port 8082.
 * <p>
 * 範例 BFF（backend-for-frontend）的程式進入點，於 8082 埠啟動。
 * <p>
 * The browser only holds a session cookie; the tokens stay in this
 * server's session, so script running in the page cannot read them
 * (detailed design D03).
 * <p>
 * 瀏覽器只持有 Session Cookie；token 保存在本伺服器的 Session 中，頁面中的
 * 指令碼無法讀取（詳細設計 D03）。
 */
@SpringBootApplication
public class BffApplication {

    /**
     * Starts the example BFF.
     * <p>
     * 啟動範例 BFF。
     *
     * @param args  the command-line arguments passed to Spring Boot
     *              <br>傳給 Spring Boot 的命令列參數
     */
    public static void main(String[] args) {
        SpringApplication.run(BffApplication.class, args);
    }
}
