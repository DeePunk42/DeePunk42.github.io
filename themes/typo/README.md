<h1 align="center">typo</h1>

<p align="center">一个简单的 hexo 主题</p>

<p align='center'>
简体中文 ｜ <a href="https://github.com/rankangkang/hexo-theme-typo/blob/main/README.en.md">English</a>
</p>

## ✨ 特性

- 代码高亮
  - light mode: atom-one-light
- 多样字体
  - 文章使用 Montserrat 字体
  - 代码使用 JetBrains Mono 字体

## 📦 安装

```bash
git clone --depth=1 https://github.com/rankangkang/hexo-theme-typo.git themes/typo
```

并在 `_config.yaml` 中进行如下配置：

```yaml _config.yaml
theme: typo
```

## 🌈 配置

### 代码高亮

主题使用 highlight.js 高亮代码，为此，您需要事先禁用默认的 highlight 配置。

```yaml _config.yaml
highlight:
  line_number: false
  auto_detect: false
  tab_replace: ''
  wrap: false
  hljs: false
```

### theme 配置项

typo 对外提供了一些自定义配置，在 `typo/_config.yaml` 下配置即可。

- `title`：网站标题
- `favicon`: favicon（指向的文件需放置在 source 目录下）
- `icon`: 网站图标（指向的文件需放置在 source 目录下）
- `menu`: 菜单导航
- `copyright`: 底栏 copyright 展示内容

默认配置如下：

```yaml typo/_config.yaml
title: typo
favicon: /icon.svg
icon: /icon.svg

menu:
  archives: /archives
  about: /about

copyright: 2024 typo
```

## 🔗 想要开发一个自己的主题？

👉🏻 来 [这里](https://github.com/rankangkang/hexo-themes) 快速开始，这可能会很有帮助 ~

😁 Happy coding ~
