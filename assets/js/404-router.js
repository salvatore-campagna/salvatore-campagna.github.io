(function() {
  document.body.classList.add('four04-takeover');

  var variants = ['gc', 'bytecode'];
  var pick = variants[Math.floor(Math.random() * variants.length)];

  var el = document.getElementById('variant-' + pick);
  if (el) el.classList.add('active');

  var scriptMap = {
    'gc': '/assets/js/404-gc.js',
    'bytecode': '/assets/js/404-bytecode.js'
  };

  var script = document.createElement('script');
  script.src = scriptMap[pick];
  document.body.appendChild(script);
})();
