hexo.extend.filter.register('after_render:html', function (html) {
  // 1. 抓取段落形式的脚注定义：<p>[^N]: ...</p>
  //    （markdown 里写 [^N]: [text](url) 或 [^N]: 任意 markdown，
  //     marked 不识别为引用定义时会留成普通段落）
  var fnMap = {};
  html = html.replace(
    /<p>\[\^(\d+)\]:\s*([\s\S]*?)<\/p>\s*/g,
    function (match, num, content) {
      fnMap[num] = content.trim();
      return '';
    }
  );

  // 2. 兼容旧写法：[^N]: URL 或 [^N]: URL "title"
  //    被 marked 识别为引用链接定义时，正文 [^N] 会渲染成 <a>...^N</a>
  html = html.replace(
    /<a([^>]*?)>\^(\d+)<\/a>/g,
    function (match, attrs, num) {
      var hrefMatch = attrs.match(/href="([^"]+)"/);
      var titleMatch = attrs.match(/title="([^"]+)"/);
      if (!hrefMatch) return match;

      var url = hrefMatch[1];
      var content = titleMatch ? url + ' "' + titleMatch[1] + '"' : url;

      var sup =
        '<sup class="sidenote-ref"><a href="' + url +
        '" target="_blank" rel="noopener">' + num + '</a></sup>';
      var sidenote =
        '<span class="sidenote">' +
        '<span class="sidenote-num">' + num + '.</span> ' +
        content +
        '</span>';
      return sup + sidenote;
    }
  );

  // 3. 替换正文里残留的字面 [^N]，用 fnMap 里抓到的脚注内容生成 sidenote
  html = html.replace(
    /\[\^(\d+)\]/g,
    function (match, num) {
      var content = fnMap[num];
      if (!content) return match;

      // 若脚注内容里有链接，让上标也指向第一个 URL
      var firstUrl = (content.match(/href="([^"]+)"/) || [])[1];
      var sup = firstUrl
        ? '<sup class="sidenote-ref"><a href="' + firstUrl +
          '" target="_blank" rel="noopener">' + num + '</a></sup>'
        : '<sup class="sidenote-ref">' + num + '</sup>';
      var sidenote =
        '<span class="sidenote">' +
        '<span class="sidenote-num">' + num + '.</span> ' +
        content +
        '</span>';
      return sup + sidenote;
    }
  );

  return html;
});
