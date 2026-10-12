package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.admin.ClientAdminService.ClientRequest;
import jacky917.security.authorizationserver.admin.ClientAdminService.ClientUpdate;
import jacky917.security.authorizationserver.admin.ClientAdminService.ClientView;
import jacky917.security.authorizationserver.admin.ClientAdminService.CreatedClient;
import jacky917.security.authorizationserver.admin.ClientAdminService.StatusChange;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Clients in the administration API (phase 3 and 4 design §6.4).
 * <p>
 * 管理 API 中的 client（第 3、4 階段設計 §6.4）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api/clients")
public class ClientAdminController {

    private final ClientAdminService clients;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param clients  manages clients
     *                 <br>管理 client
     */
    public ClientAdminController(ClientAdminService clients) {
        this.clients = clients;
    }

    /**
     * Lists the clients, including those in the configuration.
     * <p>
     * 列出 client，包含設定檔中的 client。
     *
     * @return the clients, by client id
     *         <br>client，依 client id 排序
     */
    @GetMapping
    public List<ClientView> clients() {
        return clients.clients();
    }

    /**
     * Creates a third-party client.
     * <p>
     * 建立第三方 client。
     *
     * @param request  the client
     *                 <br>client
     * @return the client and its secret, shown only now
     *         <br>client 與其 secret，只在此時顯示
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CreatedClient create(@RequestBody ClientRequest request) {
        return clients.create(request);
    }

    /**
     * Returns a client.
     * <p>
     * 回傳一個 client。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client
     *         <br>client
     */
    @GetMapping("/{clientId}")
    public ClientView client(@PathVariable String clientId) {
        return clients.client(clientId);
    }

    /**
     * Changes the given fields of a client.
     * <p>
     * 變更 client 的指定欄位。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @param request   the fields to change
     *                  <br>要變更的欄位
     * @return the client
     *         <br>client
     */
    @PatchMapping("/{clientId}")
    public ClientView update(@PathVariable String clientId, @RequestBody ClientUpdate request) {
        return clients.update(clientId, request);
    }

    /**
     * Replaces the secret of a client.
     * <p>
     * 取代 client 的 secret。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client and its new secret, shown only now
     *         <br>client 與新的 secret，只在此時顯示
     */
    @PostMapping("/{clientId}/secret")
    public CreatedClient regenerateSecret(@PathVariable String clientId) {
        return clients.regenerateSecret(clientId);
    }

    /**
     * Approves a client under review.
     * <p>
     * 核准審核中的 client。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client
     *         <br>client
     */
    @PostMapping("/{clientId}/approve")
    public ClientView approve(@PathVariable String clientId) {
        return clients.changeStatus(clientId, StatusChange.APPROVE);
    }

    /**
     * Suspends a client and deletes its authorizations.
     * <p>
     * 停權 client，並刪除它的授權。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client
     *         <br>client
     */
    @PostMapping("/{clientId}/suspend")
    public ClientView suspend(@PathVariable String clientId) {
        return clients.changeStatus(clientId, StatusChange.SUSPEND);
    }

    /**
     * Activates a suspended client.
     * <p>
     * 重新啟用已停權的 client。
     *
     * @param clientId  the client id
     *                  <br>client id
     * @return the client
     *         <br>client
     */
    @PostMapping("/{clientId}/activate")
    public ClientView activate(@PathVariable String clientId) {
        return clients.changeStatus(clientId, StatusChange.ACTIVATE);
    }

    /**
     * Deletes a client with its authorizations and consents.
     * <p>
     * 刪除 client，以及它的授權與同意紀錄。
     *
     * @param clientId  the client id
     *                  <br>client id
     */
    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String clientId) {
        clients.delete(clientId);
    }
}
