#!/bin/bash
set -ex

git add .
git commit -m "regular push at $(date "+%Y%m%d_%H%M%S")"
git push origin hexo

hexo g -d
