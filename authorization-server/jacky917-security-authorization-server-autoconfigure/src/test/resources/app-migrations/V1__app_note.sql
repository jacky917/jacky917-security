-- 測試用：代表應用程式自己的 migration（與 Authorization Server 的 migration 共用同一個資料庫）
CREATE TABLE app_note (
    id   VARCHAR(36) NOT NULL PRIMARY KEY,
    body TEXT
);
