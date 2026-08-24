#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(git branch --show-current)" != "hexo" ]]; then
  echo "请先切换到 hexo 分支再发布。" >&2
  exit 1
fi

echo "正在安装锁定版本的依赖……"
npm ci

echo "正在检查能否正常生成站点……"
npm run check

git add --all
if git diff --cached --quiet; then
  echo "源码没有需要提交的改动。"
else
  commit_message="${1:-blog: update $(date '+%Y-%m-%d %H:%M:%S')}"
  git commit -m "$commit_message"
fi

git push origin hexo

echo "正在发布生成后的静态站点到 master 分支……"
npm run deploy

echo "发布完成：https://deepunk.icu"
