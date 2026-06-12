// 0. 渲染前：
//    a) 转义 [^N]: 定义行首的方括号，避免 marked 把它当成
//       reference link definition（脚注内容以 [text](url) 开头时会被吞掉）
//    b) 在每个 [^N]: 前插入一个空行，确保每条定义渲染成独立的 <p>，
//       否则相邻定义会被合并成单个 <p>...<br>...</p>，导致 after_render
//       的非贪婪正则把后续脚注的内容也吞进首条脚注
hexo.extend.filter.register('before_post_render', function (data) {
  if (!data || typeof data.content !== 'string') return data;
  data.content = data.content.replace(
    /^[ \t]*\[\^(\d+)\]:/gm,
    '\n\\[\\^$1\\]:'
  );
  return data;
});

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
  //    同一脚注重复出现时，只在首次展开内容，后续仅留 sup 跳转链接
  var fnSeen = {};
  html = html.replace(
    /\[\^(\d+)\]/g,
    function (match, num) {
      var content = fnMap[num];
      if (!content) return match;
      if (fnOrder.indexOf(num) === -1) fnOrder.push(num);

      var sup =
        '<sup class="sidenote-ref"><a href="#fn-' + num + '">' + num + '</a></sup>';
      if (fnSeen[num]) return sup;
      fnSeen[num] = true;

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
