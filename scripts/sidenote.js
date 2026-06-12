hexo.extend.filter.register('after_render:html', function (html) {
  var fnMap = {};
  var fnOrder = [];

  // 1. 抓取段落形式的脚注定义：<p>[^N]: ...</p>
  html = html.replace(
    /<p>\[\^(\d+)\]:\s*([\s\S]*?)<\/p>\s*/g,
    function (match, num, content) {
      fnMap[num] = content.trim();
      return '';
    }
  );

  // 2. 兼容旧写法：[^N]: URL 或 [^N]: URL "title"
  html = html.replace(
    /<a([^>]*?)>\^(\d+)<\/a>/g,
    function (match, attrs, num) {
      var hrefMatch = attrs.match(/href="([^"]+)"/);
      var titleMatch = attrs.match(/title="([^"]+)"/);
      if (!hrefMatch) return match;

      var url = hrefMatch[1];
      var content = titleMatch ? url + ' "' + titleMatch[1] + '"' : url;
      fnMap[num] = content;
      if (fnOrder.indexOf(num) === -1) fnOrder.push(num);

      var sup =
        '<sup class="sidenote-ref"><a href="#fn-' + num + '">' + num + '</a></sup>';
      var sidenote =
        '<span class="sidenote">' +
        '<span class="sidenote-num">' + num + '.</span> ' +
        content +
        '</span>';
      return sup + sidenote;
    }
  );

  // 3. 替换字面 [^N]，用 fnMap 里抓到的内容生成 sidenote
  html = html.replace(
    /\[\^(\d+)\]/g,
    function (match, num) {
      var content = fnMap[num];
      if (!content) return match;
      if (fnOrder.indexOf(num) === -1) fnOrder.push(num);

      var sup =
        '<sup class="sidenote-ref"><a href="#fn-' + num + '">' + num + '</a></sup>';
      var sidenote =
        '<span class="sidenote">' +
        '<span class="sidenote-num">' + num + '.</span> ' +
        content +
        '</span>';
      return sup + sidenote;
    }
  );

  // 4. 在 .post-content 末尾插入 Ref 章节（窄屏会显示，宽屏 CSS 隐藏）
  if (fnOrder.length > 0) {
    var refHtml = '<section class="footnotes-list"><h1>Ref</h1><ol>';
    fnOrder.forEach(function (num) {
      refHtml +=
        '<li id="fn-' + num + '">' +
        '<span class="footnote-num">' + num + '.</span> ' +
        fnMap[num] +
        '</li>';
    });
    refHtml += '</ol></section>';

    html = html.replace(
      /(<main class="post-content">[\s\S]*?)(<\/main>)/,
      '$1' + refHtml + '$2'
    );
  }

  return html;
});
