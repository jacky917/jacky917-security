package jacky917.demo.resourceserver.clip;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * JPA entity for a clip, used to demonstrate database-backed ABAC.
 * <p>
 * Clip 的 JPA 實體，用於示範以資料庫為依據的 ABAC 判斷。
 */
@Entity
@Table(name = "clip")
public class Clip {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    /**
     * Creates an empty clip; required by JPA.
     * <p>
     * 建立空的 clip，供 JPA 使用。
     */
    public Clip() {
    }

    /**
     * Creates a clip with the given ID, name, and owner.
     * <p>
     * 以指定的 ID、名稱與擁有者建立 clip。
     *
     * @param id       the clip ID, at most 64 characters
     *                 <br>clip ID，最多 64 個字元
     * @param name     the display name, at most 128 characters
     *                 <br>顯示名稱，最多 128 個字元
     * @param ownerId  the owner's user name (JWT {@code sub}), at most 128
     *                 characters
     *                 <br>擁有者的使用者名稱（JWT {@code sub}），最多 128 個字元
     */
    public Clip(String id, String name, String ownerId) {
        this.id = id;
        this.name = name;
        this.ownerId = ownerId;
    }

    /**
     * Returns the ID of this clip.
     * <p>
     * 回傳此 clip 的 ID。
     *
     * @return the clip ID
     *         <br>clip ID
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the display name of this clip.
     * <p>
     * 回傳此 clip 的顯示名稱。
     *
     * @return the display name
     *         <br>顯示名稱
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the user name of this clip's owner.
     * <p>
     * 回傳此 clip 擁有者的使用者名稱。
     *
     * @return the owner's user name, compared with the JWT {@code sub}
     *         <br>擁有者的使用者名稱，用於與 JWT {@code sub} 比對
     */
    public String getOwnerId() {
        return ownerId;
    }

    /**
     * Sets the ID of this clip.
     * <p>
     * 設定此 clip 的 ID。
     *
     * @param id  the clip ID, at most 64 characters
     *            <br>clip ID，最多 64 個字元
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Sets the display name of this clip.
     * <p>
     * 設定此 clip 的顯示名稱。
     *
     * @param name  the display name, at most 128 characters
     *              <br>顯示名稱，最多 128 個字元
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the user name of this clip's owner.
     * <p>
     * 設定此 clip 擁有者的使用者名稱。
     *
     * @param ownerId  the owner's user name, at most 128 characters
     *                 <br>擁有者的使用者名稱，最多 128 個字元
     */
    public void setOwnerId(String ownerId) {
        this.ownerId = ownerId;
    }
}

