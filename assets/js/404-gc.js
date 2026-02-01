(function() {
  var now = new Date();
  var ts = now.toISOString().replace('T', ' ').substring(0, 23);
  var path = window.location.pathname;

  var lines = [
    { delay: 0, text: '[' + ts + '] [info ] [JVM] Using OpenJDK 21.0.2+13 with G1 Garbage Collector', type: 'info' },
    { delay: 400, text: '[' + ts + '] [info ] [heap] Initial heap: 256M | Max heap: 4096M | Used: 1847M', type: 'info' },
    { delay: 800, text: '[' + ts + '] [info ] [blog] Resolving path: ' + path, type: 'warn' },
    { delay: 1400, text: '[' + ts + '] [warn ] [blog] PageCache.lookup() returned null for ' + path, type: 'warn' },
    { delay: 1900, text: '[' + ts + '] [warn ] [blog] ContentResolver.loadPage() \u2014 file not found on disk', type: 'warn' },
    { delay: 2500, text: '[' + ts + '] [error] [blog] Page object unreachable. Marking for collection.', type: 'error' },
    { delay: 3200, text: '', type: 'blank' },
    { delay: 3400, text: '[' + ts + '] [info ] [gc  ] GC(404) Pause Young (Normal) (Page Not Found)', type: 'gc' },
    { delay: 3900, text: '[' + ts + '] [info ] [gc  ] GC(404)   ParNew: 1847M->1203M(2048M)', type: 'gc' },
    { delay: 4300, text: '[' + ts + '] [info ] [gc  ] GC(404)   Heap: 3012M->2368M(4096M)', type: 'gc' },
    { delay: 4700, text: '[' + ts + '] [info ] [gc  ] GC(404)   Collected: 1 dead page object (644M reclaimed)', type: 'gc-error' },
    { delay: 5200, text: '[' + ts + '] [info ] [gc  ] GC(404)   Pause: 4.04ms', type: 'gc' },
    { delay: 5700, text: '', type: 'blank' },
    { delay: 5900, text: '[' + ts + '] [info ] [gc  ] GC(404) Concurrent Mark \u2014 scanning live objects...', type: 'gc' },
    { delay: 6500, text: '[' + ts + '] [info ] [gc  ] GC(404)   Live roots found: HomePageBean, ArchiveIndex, TagRegistry, CategoryMapper, AuthorProfile', type: 'gc-success' },
    { delay: 7200, text: '[' + ts + '] [info ] [gc  ] GC(404)   Dead objects: ' + path + ' (softly reachable, finalized)', type: 'gc-error' },
    { delay: 7800, text: '[' + ts + '] [info ] [gc  ] GC(404) Concurrent Mark \u2014 2.87ms', type: 'gc' },
    { delay: 8400, text: '', type: 'blank' },
    { delay: 8600, text: '[' + ts + '] [info ] [gc  ] GC(404) Pause Remark \u2014 0.42ms', type: 'gc' },
    { delay: 9000, text: '[' + ts + '] [info ] [gc  ] GC(404) Concurrent Cleanup \u2014 0.18ms', type: 'gc' },
    { delay: 9500, text: '', type: 'blank' },
    { delay: 9700, text: '[' + ts + '] [info ] [gc  ] GC(404) Collection complete. Page successfully garbage collected.', type: 'success' },
    { delay: 10300, text: '[' + ts + '] [info ] [heap] Heap after GC: 2368M used / 4096M committed / 0 dead pages', type: 'success' }
  ];

  var colorMap = {
    'info': '#61afef',
    'warn': '#e5c07b',
    'error': '#e06c75',
    'gc': '#c678dd',
    'gc-error': '#e06c75',
    'gc-success': '#98c379',
    'success': '#98c379',
    'blank': 'transparent'
  };

  var output = document.getElementById('gc-output');
  var nav = document.getElementById('gc-nav');
  if (!output || !nav) return;

  lines.forEach(function(line, i) {
    setTimeout(function() {
      var div = document.createElement('div');
      div.className = 'line';
      div.style.animationDelay = '0s';

      if (line.type === 'blank') {
        div.innerHTML = '\u00a0';
      } else {
        var span = document.createElement('span');
        span.style.color = colorMap[line.type] || '#abb2bf';
        span.textContent = line.text;
        div.appendChild(span);
      }

      var prev = output.querySelector('.cursor');
      if (prev) prev.parentNode.removeChild(prev);

      if (line.type !== 'blank') {
        var cursor = document.createElement('span');
        cursor.className = 'cursor';
        div.appendChild(cursor);
      }

      output.appendChild(div);
      output.scrollTop = output.scrollHeight;

      if (i === lines.length - 1) {
        setTimeout(function() {
          var c = output.querySelector('.cursor');
          if (c) c.parentNode.removeChild(c);
          nav.style.display = 'block';
        }, 800);
      }
    }, line.delay);
  });
})();
