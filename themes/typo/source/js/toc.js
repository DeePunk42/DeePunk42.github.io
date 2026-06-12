(function () {
  'use strict';

  function throttle(fn, wait) {
    var last = 0;
    var timer = null;
    return function () {
      var now = Date.now();
      var remaining = wait - (now - last);
      var ctx = this;
      var args = arguments;
      if (remaining <= 0) {
        if (timer) { clearTimeout(timer); timer = null; }
        last = now;
        fn.apply(ctx, args);
      } else if (!timer) {
        timer = setTimeout(function () {
          last = Date.now();
          timer = null;
          fn.apply(ctx, args);
        }, remaining);
      }
    };
  }

  function init() {
    var content = document.querySelector('.post-content');
    if (!content) return;

    var headings = Array.prototype.slice.call(
      content.querySelectorAll('h1, h2, h3, h4')
    ).filter(function (h) { return h.id; });
    if (headings.length === 0) return;

    var topLevel = headings.reduce(function (min, h) {
      var l = parseInt(h.tagName.charAt(1), 10);
      return l < min ? l : min;
    }, 6);

    var tree = [];
    var currentTop = null;
    headings.forEach(function (h) {
      var level = parseInt(h.tagName.charAt(1), 10);
      if (level === topLevel) {
        currentTop = { heading: h, children: [] };
        tree.push(currentTop);
      } else if (currentTop) {
        currentTop.children.push(h);
      }
    });
    if (tree.length === 0) return;

    var aside = document.createElement('aside');
    aside.className = 'post-toc';
    var list = document.createElement('ul');
    list.className = 'toc-list';

    tree.forEach(function (item) {
      var li = document.createElement('li');
      li.className = 'toc-item';
      li.dataset.target = item.heading.id;

      var line = document.createElement('span');
      line.className = 'toc-line';
      li.appendChild(line);

      var link = document.createElement('a');
      link.className = 'toc-text';
      link.href = '#' + item.heading.id;
      link.textContent = item.heading.textContent;
      li.appendChild(link);

      if (item.children.length > 0) {
        var sub = document.createElement('ul');
        sub.className = 'toc-sublist';
        item.children.forEach(function (c) {
          var subLi = document.createElement('li');
          var subA = document.createElement('a');
          subA.href = '#' + c.id;
          subA.textContent = c.textContent;
          subLi.appendChild(subA);
          sub.appendChild(subLi);
        });
        li.appendChild(sub);
      }

      list.appendChild(li);
    });

    aside.appendChild(list);
    document.body.appendChild(aside);

    var items = Array.prototype.slice.call(list.querySelectorAll('.toc-item'));
    var tops = tree.map(function (t) { return t.heading; });

    function setActive(heading) {
      items.forEach(function (it) { it.classList.remove('active'); });
      if (!heading) return;
      for (var i = 0; i < items.length; i++) {
        if (items[i].dataset.target === heading.id) {
          items[i].classList.add('active');
          return;
        }
      }
    }

    var update = throttle(function () {
      var current = null;
      var threshold = 100;
      for (var i = 0; i < tops.length; i++) {
        if (tops[i].getBoundingClientRect().top < threshold) {
          current = tops[i];
        } else {
          break;
        }
      }
      setActive(current);
    }, 100);

    window.addEventListener('scroll', update, { passive: true });
    update();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
