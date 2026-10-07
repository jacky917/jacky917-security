package jacky917.demo.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the demo authorization server, which issues test JWTs on
 * port 8081.
 * <p>
 * Demo Authorization Server 的程式進入點，於 8081 埠簽發測試用 JWT。
 */
@SpringBootApplication
public class DemoAuthorizationServerApplication {

    /**
     * Starts the demo authorization server.
     * <p>
     * 啟動 Demo Authorization Server。
     *
     * @param args  the command-line arguments passed to Spring Boot
     *              <br>傳給 Spring Boot 的命令列參數
     */
    public static void main(String[] args) {
        SpringApplication.run(DemoAuthorizationServerApplication.class, args);
    }
}

