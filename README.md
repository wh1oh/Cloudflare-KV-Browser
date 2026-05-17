# KV 文件管理器 — Cloudflare Pages

网页登录密码保护的 KV 存储文件浏览器，支持上传、下载、删除文件。

---

## 部署步骤

### 1. 上传项目文件

**方式一：直接上传（推荐）**

1. 进入 [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages**
2. 点击 **Create** → **Pages** → **Upload assets**
3. 输入项目名称，上传 `_worker.js` 文件，点击 **Deploy site**

**方式二：连接 Git 仓库**

1. **Workers & Pages** → **Create** → **Pages** → **Connect to Git**
2. 选择仓库，Framework preset 选 **None**，直接部署

---

### 2. 设置环境变量

**Workers & Pages → 你的项目 → Settings → Environment variables → Production**，添加以下变量：

| 变量名 | 值 | 类型 |
|--------|-----|------|
| `USER` | 你的登录用户名 | Secret |
| `PASSWORD` | 你的登录密码 | Secret |
| `SECRET_KEY` | 随机字符串（建议 32 字节以上） | Secret |

> ⚠️ 三个变量均建议设置为 **Secret** 类型，防止泄漏。设置后需重新部署才生效。

生成 `SECRET_KEY` 的方法：
```bash
openssl rand -hex 32
```

---

### 3. 创建 KV 命名空间

1. 进入 **Workers & Pages** → **KV**
2. 点击 **Create a namespace**
3. 输入命名空间名称（如 `MY_FILES`），点击 **Add**

> 可以创建多个 KV 命名空间，每个命名空间在界面中作为独立分组显示。

---

### 4. 绑定 KV 到项目

1. 进入 **Workers & Pages → 你的项目 → Settings → Bindings**
2. 点击 **Add** → 选择 **KV namespace**
3. 填写绑定配置：

| 字段 | 值 |
|------|----|
| **Variable name** | 任意自定义（如 `MY_FILES`），即界面下拉中显示的名称 |
| **KV namespace** | 选择第 3 步创建的 KV 命名空间 |

4. 点击 **Save**
5. 重新部署项目使绑定生效：**Deployments → 最新部署 → Manage → Retry deployment**

> 💡 可以绑定多个 KV 命名空间，每个绑定会在侧边栏的下拉菜单中显示为独立分组。

---

## 功能说明

- 🔐 用户名 + 密码登录保护
- 🛡️ HMAC-SHA256 签名 Cookie，无状态 Session，24 小时自动过期
- 📁 支持多个 KV 命名空间切换
- ⬆️ 上传文件到指定命名空间
- ⬇️ 下载已存储的文件
- 🗑️ 删除文件（立即生效）
- 🖼️ 图片文件自动预览
- 📱 移动端响应式布局

---

## 安全说明

- Cookie 设置了 `HttpOnly` + `SameSite=Strict`，防 XSS 和 CSRF
- 密码采用恒定时间比较，防时序攻击
- Session 通过 HMAC 签名验证，无法伪造
- HTTPS 由 Cloudflare 自动保证

---

> 本项目由 [Claude AI](https://claude.ai) 编写
