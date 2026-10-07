package jacky917.demo.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the demo resource server, which shows how to use the
 * jacky917 security starter on port 8080.
 * <p>
 * Demo Resource Server 的程式進入點，於 8080 埠示範 jacky917 security
 * starter 的用法。
 */
@SpringBootApplication
public class DemoResourceServerApplication {

    /**
     * Starts the demo resource server.
     * <p>
     * 啟動 Demo Resource Server。
     *
     * @param args  the command-line arguments passed to Spring Boot
     *              <br>傳給 Spring Boot 的命令列參數
     */
    public static void main(String[] args) {
        SpringApplication.run(DemoResourceServerApplication.class, args);
    }
}

