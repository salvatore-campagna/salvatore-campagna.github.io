(function() {
  var variants = ['stacktrace', 'gc', 'ascii', 'random'];
  var pick = variants[Math.floor(Math.random() * variants.length)];

  var el = document.getElementById('variant-' + pick);
  if (el) el.classList.add('active');

  if (pick === 'gc') {
    var script = document.createElement('script');
    script.src = '/assets/js/404-gc.js';
    document.body.appendChild(script);
  } else if (pick === 'ascii') {
    var script = document.createElement('script');
    script.src = '/assets/js/404-ascii.js';
    document.body.appendChild(script);
  } else if (pick === 'random') {
    var script = document.createElement('script');
    script.src = '/assets/js/404-random-exception.js';
    document.body.appendChild(script);
  }
})();
