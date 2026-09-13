<h1 align="center">typo</h1>

<p align="center">A simple hexo theme</p>

<p align='center'>
English ｜ <a href="https://github.com/rankangkang/hexo-theme-typo/blob/main/README.md">简体中文</a>
</p>

## ✨ Features

- Code highlighting
  - Light mode: atom-one-light
- Multiple fonts
  - Articles use the Montserrat font
  - Code uses the JetBrains Mono font

## Installation

```bash
git clone --depth=1 https://github.com/rankangkang/hexo-theme-typo.git themes/typo
```

And configure in _config.yaml:

```yaml _config.yaml
theme: typo
```

## 🌈 Configuration

### Code Highlighting

Typo uses highlight.js to highlight code. To do this, you need to disable the default highlight configuration beforehand.

```yaml _config.yaml
highlight:
  line_number: false
  auto_detect: false
  tab_replace: ''
  wrap: false
  hljs: false
```

### Theme Config

Typo provides some customization options, which can be configured in `typo/_config.yaml`.

- `title`: website title
- `favicon`: favicon (the file should be placed in the source directory)
- `icon`: website icon (the file should be placed in the source directory)
- `menu`: menu navigation
- `copyright`: footer copyright

Default configuration is as follows:

```yaml typo/_config.yaml
title: typo
favicon: /icon.svg
icon: /icon.svg

menu:
  archives: /archives
  about: /about

copyright: 2024 typo
```

## 🔗 Wanna build your own hexo theme?

👉🏻 Fork this [repo](https://github.com/rankangkang/hexo-themes) to get started quickly.

😁 This is a simple pnpm monorepo template to help you develop Hexo themes.
