(function() {
  document.body.classList.add('four04-takeover');

  var el = document.getElementById('variant-gc');
  if (el) el.classList.add('active');

  var script = document.createElement('script');
  script.src = '/assets/js/404-gc.js';
  document.body.appendChild(script);
})();
