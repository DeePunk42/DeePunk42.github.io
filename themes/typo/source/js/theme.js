(function () {
  var STORAGE_KEY = 'theme';
  var HLJS_LIGHT =
    'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-light.css';
  var HLJS_DARK =
    'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.css';
  var ICON_LIGHT = '☾'; // ☾  显示"切到暗色"
  var ICON_DARK = '☀';  // ☀  显示"切到亮色"

  function systemPrefersDark() {
    try {
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (e) {
      return false;
    }
  }

  function storedTheme() {
    try {
      var t = localStorage.getItem(STORAGE_KEY);
      return t === 'light' || t === 'dark' ? t : null;
    } catch (e) {
      return null;
    }
  }

  function currentTheme() {
    return storedTheme() || (systemPrefersDark() ? 'dark' : 'light');
  }

  function applyTheme(t, animate) {
    var html = document.documentElement;

    if (animate) {
      html.classList.add('theme-transitioning');
      setTimeout(function () {
        html.classList.remove('theme-transitioning');
      }, 350);
    }

    html.setAttribute('data-theme', t);

    var link = document.querySelector('link#theme');
    if (link) {
      var nextHref = t === 'dark' ? HLJS_DARK : HLJS_LIGHT;
      if (link.href !== nextHref) link.href = nextHref;
    }

    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.textContent = t === 'dark' ? ICON_DARK : ICON_LIGHT;
      btn.setAttribute('aria-label', t === 'dark' ? '切换到浅色' : '切换到深色');
    }
  }

  applyTheme(currentTheme(), false);

  function bindToggle() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch (e) {}
      applyTheme(next, true);
    });
  }

  if (document.readyState !== 'loading') {
    bindToggle();
  } else {
    document.addEventListener('DOMContentLoaded', bindToggle);
  }

  try {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var sysListener = function (e) {
      if (!storedTheme()) {
        applyTheme(e.matches ? 'dark' : 'light', true);
      }
    };
    if (mq.addEventListener) mq.addEventListener('change', sysListener);
    else if (mq.addListener) mq.addListener(sysListener);
  } catch (e) {}
})();
