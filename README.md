# DeePunk 的博客

这是一个使用 [Hexo](https://hexo.io/) 和 `typo` 主题生成的静态博客：

- `hexo` 分支保存文章、主题与配置（平时只在这个分支工作）。
- `master` 分支保存 Hexo 生成的网页，由 GitHub Pages 对外发布。
- 线上地址为 <https://deepunk.icu>。

## 首次配置

建议使用 Node.js 22。安装 Node.js 后，在仓库目录执行：

```bash
# 使用 nvm 时会自动读取仓库内的 .nvmrc
nvm use
npm ci
```

如果没有安装 `nvm`，直接使用 Node.js 20.19 或更高版本即可。然后启动本地预览：

```bash
npm run server
```

浏览器访问 <http://localhost:4000>。修改文章或主题后刷新页面即可看到结果；按 `Ctrl+C` 停止预览。

## 写新文章

在 `hexo` 分支执行：

```bash
npm run new -- "文章标题"
```

新文件会生成在 `source/_posts/文章标题.md`。文章开头使用以下格式：

```yaml
---
title: 文章标题
date: 2026-08-25 20:00:00
tags:
  - pwn
categories:
  - CS
excerpt: 显示在首页的一句话摘要
---
```

正文使用 Markdown。图片建议放入 `source/img/` 的独立子目录，并在文章中使用站点根路径引用：

```markdown
![图片说明](/img/文章标题/example.png)
```

写完后先检查：

```bash
npm run check
npm run server
```

## 更新并发布

确认本地预览没有问题后，执行：

```bash
./push.sh "blog: 发布文章标题"
```

脚本会依次完成构建检查、提交并推送 `hexo` 源码分支，以及生成并推送 `master` 发布分支。发布通常需要几十秒到几分钟才会出现在站点上。

运行脚本前需要满足：

1. 当前位于 `hexo` 分支；
2. 本机的 GitHub SSH key 可以访问 `git@github.com:DeePunk42/DeePunk42.github.io.git`；
3. GitHub Pages 的发布来源是 `master` 分支的根目录；
4. 自定义域名配置为 `deepunk.icu`，并开启 Enforce HTTPS。

只想手动提交源码、不立即发布网页时，可以使用普通 Git 命令：

```bash
git add source _config.yml themes
git commit -m "blog: 更新文章"
git push origin hexo
```

## 常用修改位置

| 内容 | 文件 |
| --- | --- |
| 站点标题、描述、网址、分页 | `_config.yml` |
| 菜单、版权、主题功能 | `themes/typo/_config.yaml` |
| 关于页面 | `source/about/index.md` |
| 文章 | `source/_posts/*.md` |
| 图片 | `source/img/` 或 `source/images/` |
| 自定义域名 | `source/CNAME` |

## 评论与安全说明

评论功能使用 Giscus，评论内容保存在本仓库的 GitHub Discussions 中。相关参数位于 `themes/typo/_config.yaml`，文章与评论按 URL 路径对应。

旧评论方案使用过公开在网页中的 GitHub OAuth Client Secret。请确认已经在 [GitHub Developer settings](https://github.com/settings/developers) 中撤销旧 secret；仅从当前文件删除并不能使历史上公开的凭据失效。

## 故障排查

- `npm ci` 失败：确认 Node.js 版本满足 `node >=20.19.0`，然后重新运行。
- 本地正常、线上没更新：查看 `master` 分支是否出现新的部署提交，并检查 GitHub Pages 设置。
- 域名失效：确认 `source/CNAME` 内容仍为 `deepunk.icu`，并检查域名 DNS。
- 发布脚本提示权限错误：使用 `ssh -T git@github.com` 检查 GitHub SSH 登录。
- 想从干净状态重建：运行 `npm run check`，不要手动提交 `public/` 目录。
