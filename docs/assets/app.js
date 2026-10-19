/* secure-kb site — zero-dependency scroll reveal + micro-interactions */
(function () {
  var els = document.querySelectorAll('.reveal');
  if (!('IntersectionObserver' in window) ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    els.forEach(function (e) { e.classList.add('in'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en, i) {
        if (en.isIntersecting) {
          // stagger siblings slightly for a soft cascade
          var d = Math.min(i * 60, 240);
          setTimeout(function () { en.target.classList.add('in'); }, d);
          io.unobserve(en.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    els.forEach(function (e) { io.observe(e); });
  }

  // active-section nav highlight
  var links = Array.prototype.slice.call(document.querySelectorAll('.nav nav a'));
  var secs = links.map(function (a) { return document.querySelector(a.getAttribute('href')); });
  if ('IntersectionObserver' in window) {
    var nav = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          links.forEach(function (a) { a.style.color = ''; });
          var idx = secs.indexOf(en.target);
          if (idx > -1) links[idx].style.color = 'var(--text)';
        }
      });
    }, { threshold: 0.4 });
    secs.forEach(function (s) { if (s) nav.observe(s); });
  }
})();
