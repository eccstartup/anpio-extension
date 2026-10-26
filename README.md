# ANP Wallet（Chrome MV3 扩展）

管理 `did:wba` 身份、注册 ANP handle、并代表网页发起 ANP-03（RFC 9421）登录签名的浏览器钱包。
只管理 Ed25519 身份密钥，不托管通信/E2EE 私钥。

## 快速开始

```bash
npm ci
npm run build
```

然后在浏览器打开 `chrome://extensions` → 打开「开发者模式」→「加载已解压的扩展程序」→ 选择本仓库的 `dist/` 目录。详细步骤见下方「导入浏览器」。

## 环境要求

- Node.js 20 或更高（构建脚本用 ESM + 顶层 await）
- npm 10 或更高
- Chrome 110 或更高（需要 Manifest V3 与 `sidePanel`）

## 安装依赖

```bash
npm ci
```

没有 `package-lock.json` 时改用 `npm install`。

## 构建

```bash
npm run build
```

产物全部生成到 `dist/`：

```
dist/
├── manifest.json
├── background.js
├── content.js
├── injected.js
├── popup.html
├── popup.js
├── popup.css
└── icons/icon-{16,48,128}.png
```

`dist/` 由 `build.mjs` 完整生成，包括图标（脚本现画，不需要手工放图）。它是构建产物，已加入 `.gitignore`，不要提交。

## 导入浏览器（本地使用）

构建完成后，把 `dist/` 作为「已解压的扩展程序」导入浏览器即可，不需要打包 zip。

Chrome / Edge：

1. 打开 `chrome://extensions`（Edge 为 `edge://extensions`）。
2. 打开右上角（Edge 在左下角）的「开发者模式」；不开这个开关，看不到「加载已解压的扩展程序」。
3. 点「加载已解压的扩展程序」，在文件选择框里选中本仓库的 **`dist/` 目录本身**——选 `dist`，不要选仓库根目录，也不要选 `dist` 里的某个文件。
4. 导入后工具栏会出现 ANP Wallet 图标；点它打开侧边栏。图标可能被收进「扩展程序」拼图菜单里，可以把它固定到工具栏。
5. 首次使用在侧边栏里创建钱包（生成助记词或导入 Ed25519 私钥），设置全局密码，然后注册身份。

更新代码之后：

```bash
npm run build
```

回到 `chrome://extensions`，点该扩展卡片上的刷新按钮（↻）。改了 `background.ts` 必须刷新扩展；只改页面脚本时，扩展刷新后还要刷新一下目标网页，新的 `content.js` / `injected.js` 才会注入。

常见问题：

- 加载时报 manifest 相关错误：多半是选错了目录，确认选的是构建出来的 `dist/`。
- 侧边栏打不开 / 扩展图标点了没反应：先确认扩展已启用，再刷新扩展。
- 改了代码但行为没变：`npm run build` → 刷新扩展 → 刷新网页，三步缺一不可。


## 打包成 zip 分发（可选）

先升版本号：`src/manifest.json` 的 `version` 和 `package.json` 的 `version` 改成同一个新版本，再构建：

```bash
npm run build
```

然后把 **`dist/` 里的内容**打成 zip（`manifest.json` 必须位于压缩包根目录，不能套一层 `dist/`）：

```bash
(cd dist && zip -r ../anp-wallet-$(node -p "require('../package.json').version").zip .)
```

产物为仓库根目录下的 `anp-wallet-<version>.zip`，可用于 Chrome Web Store 上传或内部安装（解压后「加载已解压的扩展程序」）。

当前构建把 sourcemap 内联进了 js，包体会偏大。面向商店发布如果在意体积，先把 `build.mjs` 里的 `sourcemap: 'inline'` 改成 `false` 再构建。

## 校验

```bash
npm run typecheck    # TypeScript 类型检查
npm run verify:bg    # 后台逻辑 e2e（需先 npm run build，直接跑 dist/background.js）
npm run verify       # ANP-03 登录签名自测
npm run verify:did   # 真实服务器注册链路（默认走本地 open-server，见脚本内环境变量）
```

`verify:bg` 覆盖迁移、服务器管理、助记词/导入钱包、注册、邮箱验证、签名与审批等后台路径，是最省事的一次性回归。

## 权限说明

| 权限 | 用途 |
| --- | --- |
| `storage` | 保存加密后的钱包密文与设置 |
| `clipboardWrite` | 复制助记词/导出内容 |
| `sidePanel` | 侧边栏作为主界面，注册期间切换标签不会关闭 |
| `host_permissions: https://awiki.ai/*` | 默认注册服务器 |
| `optional_host_permissions: https://*/*` | 仅在添加自定义注册服务器时按需申请 |
| content scripts（`<all_urls>`） | 向页面暴露 `window.anp` 身份/签名接口 |

## 目录结构

```
src/
├── background.ts      # service worker：钱包、注册、审批、签名
├── content.ts         # ISOLATED world 中继
├── injected.ts        # MAIN world，页面可见的 window.anp
├── protocol.ts        # 消息与存储类型
├── lib/anp.ts         # DID 文档、RFC 9421、eddsa-jcs-2022
├── lib/awiki.ts       # 注册/邮箱/handle 查询
├── popup/             # 侧边栏界面（html/css/ts）
└── manifest.json
scripts/               # 验证脚本
build.mjs              # esbuild 打包
```

## 安全提示

- 助记词与私钥只在本地加密保存，密码无法找回；导出入口在「设置 → 备份与导出」。
- 签名前请在确认卡片里核对目标 URL、方法、nonce 与完整待签内容；钱包只签网站提交的内容。
- 没有 nonce 的签名请求会被直接拒绝。
