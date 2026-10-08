// 頁面只持有 BFF 的 Session Cookie；token 不會出現在瀏覽器中
const result = document.getElementById('result');

async function showUser() {
    const response = await fetch('/me');
    if (response.ok) {
        const me = await response.json();
        document.getElementById('user').textContent = `已登入：${me.name ?? me.sub}（${me.email ?? '沒有 Email'}）`;
    }
}

document.querySelectorAll('[data-api]').forEach(button => button.addEventListener('click', async () => {
    const response = await fetch(button.dataset.api);
    result.textContent = `${response.status}\n${await response.text()}`;
}));

document.getElementById('logout').addEventListener('click', async () => {
    // CSRF token 由 Spring Security 放在 XSRF-TOKEN Cookie 中，以標頭送回
    const token = document.cookie.split('; ').find(c => c.startsWith('XSRF-TOKEN='))?.split('=')[1];
    const response = await fetch('/logout', {
        method: 'POST',
        headers: {'Accept': 'application/json', ...(token ? {'X-XSRF-TOKEN': decodeURIComponent(token)} : {})}
    });
    // 前往登入服務的 /connect/logout，登出後再回到首頁
    window.location.href = response.ok ? (await response.json()).redirect : '/';
});

showUser();
