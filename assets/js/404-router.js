(function() {
  var variants = ['stacktrace', 'gc', 'ascii', 'random', 'bytecode'];
  var pick = variants[Math.floor(Math.random() * variants.length)];

  var el = document.getElementById('variant-' + pick);
  if (el) el.classList.add('active');

  var scriptMap = {
    'gc': '/assets/js/404-gc.js',
    'ascii': '/assets/js/404-ascii.js',
    'random': '/assets/js/404-random-exception.js',
    'bytecode': '/assets/js/404-bytecode.js'
  };

  if (scriptMap[pick]) {
    var script = document.createElement('script');
    script.src = scriptMap[pick];
    document.body.appendChild(script);
  }
})();
