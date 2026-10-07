package jacky917.demo.resourceserver.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Demo OpenAPI configuration that adds a bearer JWT security scheme.
 * <p>
 * Demo 用的 OpenAPI 設定，加入 bearer JWT 安全方案。
 */
@Configuration
public class DemoSwaggerConfiguration {

    /**
     * Creates the OpenAPI document that applies the {@code bearerAuth} scheme
     * to every operation, so Swagger UI shows an authorize button.
     * <p>
     * 建立將 {@code bearerAuth} 方案套用到所有 API 的 OpenAPI 文件，讓
     * Swagger UI 顯示授權按鈕。
     *
     * @return the OpenAPI definition
     *         <br>OpenAPI 定義
     */
    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        return new OpenAPI()
                .info(new Info()
                        .title("Demo Resource Server API")
                        .version("1.0")
                        .description("這是一個帶有 JWT 驗證的 Demo 服務"))
                // 1. 定義安全方案 (Security Scheme)
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")))
                // 2. 全局套用：讓所有 API 預設都顯示鎖頭
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName));
    }
}