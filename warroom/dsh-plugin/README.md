# warroom-dashboard（DSH 作战室插件）

把 `warroom/server.py`（127.0.0.1 只读实时看板）以「右下角 ⬡ 作战室 按钮 + 右侧可调宽抽屉」嵌入 DSH GUI。
同一份 bundle **web 与 desktop 两个 profile 通用**。

```
src/client.tsx   →  lib/client.js   GUI 侧：shell.overlay 注册（入口按钮 + 抽屉 iframe）
src/index.ts     →  lib/index.js    host 侧：探测/拉起 warroom 后端（detached 常驻）
cordis.patch.yml                    组合包 patch（bundle 机制用）
profile-manifest.cjs                清单/补丁读写小工具（install.ps1 调用）
install.ps1                         幂等安装/卸载
```

## 安装

```powershell
pwsh -File warroom/dsh-plugin/install.ps1                    # desktop profile（默认）
pwsh -File warroom/dsh-plugin/install.ps1 -Profile web       # web profile
pwsh -File warroom/dsh-plugin/install.ps1 -Action status     # 查看当前状态
pwsh -File warroom/dsh-plugin/install.ps1 -Action uninstall  # 回退
```

脚本做三件事：`node build.cjs` 构建 → 拷贝到 `<profile>/vendor/warroom-dashboard` 与
`<profile>/node_modules/warroom-dashboard` → 改 profile 清单。

两套等价机制（**同一 profile 只用一套**，否则同 id 注册两次）：

| profile | 机制 | 落点 |
|---|---|---|
| desktop | 组合包（bundle） | `package.json` 依赖 `file:./vendor/warroom-dashboard` + `dsh.profile.bundles` 加入 `warroom-dashboard`；loader 行由包内 `cordis.patch.yml`（`dsh.bundle.patch`）提供。插件管理器里能看到并开关这个组合包。 |
| web | profile patch | `<profile>/cordis.patch.yml` 插一条 `- insert: [- id: warroom-dashboard, name: 'warroom-dashboard']`（保持历史行为）。 |

**生效方式**：desktop / web 都带 `dsh-hmr`，清单变更可能即时重载；没出现按钮就先刷新页面，
仍不行再重启 dsh（desktop = `DeepSeek Harness.exe`，web = `dsh web`）。host 侧的后端是 detached 进程，
不随 dsh 退出，重启 dsh 不会重复拉起（端口探测幂等）。

## 配置（可选）

`$DSH_HOME/warroom.json`（默认 `~/.dsh/warroom.json`），字段级覆盖，环境变量优先：

```json
{
  "projectRoot": "D:/path/to/cairn",
  "ports": [8787, 8788, 8789],
  "host": "127.0.0.1",
  "python": "D:/path/to/cairn/.venv/Scripts/python.exe",
  "autoStart": true
}
```

环境变量：`WARROOM_PROJECT_ROOT`（旧名 `SRC_PROJECT_ROOT`）、`WARROOM_PORTS`、`WARROOM_PORT`、
`WARROOM_HOST`、`WARROOM_PYTHON`、`WARROOM_AUTOSTART`。

- `host` 默认 `0.0.0.0`（沿用旧行为，手机 / Dev Tunnel 可访问）。**只给本机用就写 `127.0.0.1`**，
  否则同一局域网内任何人都能读到看板内容。
- 解释器顺序：`python` 配置 → `<root>/.venv/Scripts/python.exe` → PATH 上的 `uv` → PATH 上的 `python`/`py`。
- 后端日志：`<projectRoot>/tmp/warroom/backend-<port>.log`（旧的实现把 stdout/stderr 丢进 `ignore`，出问题看不到原因）。

## GUI 侧行为

- 入口按钮：点击打开；**拖拽移动**；**双击**切紧凑图标态；位置/紧凑态持久化。
- 抽屉：左边缘**拖拽调宽**；`⟳ 重载` 重挂 iframe；`↗ 浏览器` 用系统浏览器打开同一地址。
- 快捷键：`Esc` 关闭；`Ctrl/Cmd+Alt+W` 开关。
- 打开前先做**协议级探活**（`no-cors` fetch `/api/targets`，最多重试约 16s），避免后端刚被拉起时抽屉里只有浏览器错误页；
  已就绪后每 20s 复检，后端挂了就换回可重试提示。
- 地址解析：`localStorage['warroom.url']` 覆盖 → Dev Tunnel 端口映射（`xxx-3080.asse.devtunnels.ms` → `xxx-8787`）→ 当前 host 的 8787/8788/8789。
- 探活的 `no-cors` 是刻意的：默认 `cors` 模式下跨域读响应会被 CORS 拦截，会误报「后端未就绪」。

## 关键约束（改之前先看）

1. `package.json` 里的 `dsh.client.platform` **必须保持 `"web"`**。
   `@deepseek-ai/dsh-client-modules` 只认这个字面量（`decl.platform !== "web"` 直接跳过），
   desktop 壳走的是「shell carrier + fetchBundle」，同一份客户端 bundle，不是另一个平台值。
2. 包内**不要声明 `peerDependencies: {"@deepseek-ai/dsh-*": ...}`**：组合包加载时会做兼容性检查，
   不匹配且无豁免的组合包会被整个跳过（`skippedBundles`）。当前不声明即免检。
3. `dsh.bundle.patch` 的文件必须存在且是合法的 patch 列表（`- insert: [...]`），否则该组合包被跳过。
4. 后端默认 bind `0.0.0.0`，见上方 `host` 的安全提示。
