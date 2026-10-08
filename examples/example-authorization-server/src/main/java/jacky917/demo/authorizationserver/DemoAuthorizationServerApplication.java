package jacky917.demo.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the example login service on port 9000, built on the
 * jacky917-security authorization server starter.
 * <p>
 * 範例登入服務的程式進入點，於 9000 埠啟動，以 jacky917-security
 * Authorization Server starter 建立。
 */
@SpringBootApplication
public class DemoAuthorizationServerApplication {

    /**
     * Starts the example login service.
     * <p>
     * 啟動範例登入服務。
     *
     * @param args  the command-line arguments passed to Spring Boot
     *              <br>傳給 Spring Boot 的命令列參數
     */
    public static void main(String[] args) {
        SpringApplication.run(DemoAuthorizationServerApplication.class, args);
    }
}
