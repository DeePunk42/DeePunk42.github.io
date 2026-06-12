(function () {
  function init() {
    var images = document.querySelectorAll('.post-content img');
    if (images.length === 0) return;

    var overlay = document.createElement('div');
    overlay.className = 'image-zoom-overlay';
    var zoomImg = document.createElement('img');
    zoomImg.className = 'image-zoom-target';
    overlay.appendChild(zoomImg);
    document.body.appendChild(overlay);

    function open(src, alt) {
      zoomImg.src = src;
      zoomImg.alt = alt || '';
      overlay.classList.add('open');
      document.body.classList.add('image-zoom-active');
    }

    function close() {
      overlay.classList.remove('open');
      document.body.classList.remove('image-zoom-active');
    }

    images.forEach(function (img) {
      // 若图片在链接里，让链接行为优先，不接管
      if (img.closest('a')) return;
      img.classList.add('zoomable');
      img.addEventListener('click', function () {
        open(img.currentSrc || img.src, img.alt);
      });
    });

    overlay.addEventListener('click', close);

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && overlay.classList.contains('open')) {
        close();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
