hexo.extend.filter.register('after_render:html', function (html) {
  return html.replace(
    /<p>\s*<img([^>]*?)\stitle="([^"]+)"([^>]*?)>\s*<\/p>/g,
    function (_match, before, title, after) {
      var img = '<img' + before + after + '>';
      return '<figure>' + img +
             '<figcaption>' + title + '</figcaption></figure>';
    }
  );
});
