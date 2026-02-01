(function() {
  var path = window.location.pathname;

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
  if (!output) return;

  function ts() {
    return new Date().toISOString().replace('T', ' ').substring(0, 23);
  }

  function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function appendLine(text, type) {
    var div = document.createElement('div');
    div.className = 'line';
    div.style.animationDelay = '0s';

    if (type === 'blank') {
      div.innerHTML = '\u00a0';
    } else {
      var span = document.createElement('span');
      span.style.color = colorMap[type] || '#abb2bf';
      span.textContent = text;
      div.appendChild(span);

      var prev = output.querySelector('.cursor');
      if (prev) prev.parentNode.removeChild(prev);

      var cursor = document.createElement('span');
      cursor.className = 'cursor';
      div.appendChild(cursor);
    }

    output.appendChild(div);
    output.scrollTop = output.scrollHeight;

    // Keep DOM from growing unbounded
    while (output.children.length > 200) {
      output.removeChild(output.firstChild);
    }
  }

  // --- Initial story: the page-not-found collection ---
  var intro = [
    { delay: 0,    text: '[' + ts() + '] [info ] [JVM] Using OpenJDK 21.0.2+13 with G1 Garbage Collector', type: 'info' },
    { delay: 400,  text: '[' + ts() + '] [info ] [heap] Initial heap: 256M | Max heap: 4096M | Used: 1847M', type: 'info' },
    { delay: 800,  text: '[' + ts() + '] [info ] [blog] Resolving path: ' + path, type: 'warn' },
    { delay: 1400, text: '[' + ts() + '] [warn ] [blog] PageCache.lookup() returned null for ' + path, type: 'warn' },
    { delay: 1900, text: '[' + ts() + '] [warn ] [blog] ContentResolver.loadPage() \u2014 file not found on disk', type: 'warn' },
    { delay: 2500, text: '[' + ts() + '] [error] [blog] Page object unreachable. Marking for collection.', type: 'error' },
    { delay: 3200, text: '', type: 'blank' },
    { delay: 3400, text: '[' + ts() + '] [info ] [gc  ] GC(404) Pause Young (Normal) (Page Not Found)', type: 'gc' },
    { delay: 3900, text: '[' + ts() + '] [info ] [gc  ] GC(404)   ParNew: 1847M->1203M(2048M)', type: 'gc' },
    { delay: 4300, text: '[' + ts() + '] [info ] [gc  ] GC(404)   Heap: 3012M->2368M(4096M)', type: 'gc' },
    { delay: 4700, text: '[' + ts() + '] [info ] [gc  ] GC(404)   Collected: 1 dead page object (644M reclaimed)', type: 'gc-error' },
    { delay: 5200, text: '[' + ts() + '] [info ] [gc  ] GC(404)   Pause: 4.04ms', type: 'gc' },
    { delay: 5700, text: '', type: 'blank' },
    { delay: 5900, text: '[' + ts() + '] [info ] [gc  ] GC(404) Concurrent Mark \u2014 scanning live objects...', type: 'gc' },
    { delay: 6500, text: '[' + ts() + '] [info ] [gc  ] GC(404)   Live roots found: HomePageBean, ArchiveIndex, TagRegistry, CategoryMapper, AuthorProfile', type: 'gc-success' },
    { delay: 7200, text: '[' + ts() + '] [info ] [gc  ] GC(404)   Dead objects: ' + path + ' (softly reachable, finalized)', type: 'gc-error' },
    { delay: 7800, text: '[' + ts() + '] [info ] [gc  ] GC(404) Concurrent Mark \u2014 2.87ms', type: 'gc' },
    { delay: 8400, text: '', type: 'blank' },
    { delay: 8600, text: '[' + ts() + '] [info ] [gc  ] GC(404) Pause Remark \u2014 0.42ms', type: 'gc' },
    { delay: 9000, text: '[' + ts() + '] [info ] [gc  ] GC(404) Concurrent Cleanup \u2014 0.18ms', type: 'gc' },
    { delay: 9500, text: '', type: 'blank' },
    { delay: 9700, text: '[' + ts() + '] [info ] [gc  ] GC(404) Collection complete. Page successfully garbage collected.', type: 'success' },
    { delay: 10300, text: '[' + ts() + '] [info ] [heap] Heap after GC: 2368M used / 4096M committed / 0 dead pages', type: 'success' }
  ];

  intro.forEach(function(line) {
    setTimeout(function() { appendLine(line.text, line.type); }, line.delay);
  });

  // --- Infinite background GC cycles ---
  var gcNum = 405;
  var heapUsed = 2368;
  var heapMax = 4096;

  var causes = [
    'Allocation Failure',
    'Metadata GC Threshold',
    'G1 Humongous Allocation',
    'System.gc()',
    'GCLocker Initiated GC',
    'G1 Evacuation Pause',
    'G1 Compaction Pause',
    'Heap Inspection Initiated GC',
    'Allocation Rate Adjustment'
  ];

  var collectors = [
    'ParNew', 'G1 Young', 'G1 Mixed', 'G1 Old', 'ConcurrentMarkSweep'
  ];

  function nextCycle() {
    var cause = causes[rand(0, causes.length - 1)];
    var collector = collectors[rand(0, collectors.length - 1)];
    var reclaimed = rand(50, 400);
    var before = heapUsed + reclaimed;
    if (before > heapMax) before = heapMax - rand(10, 100);
    heapUsed = before - reclaimed;
    if (heapUsed < 800) heapUsed = rand(800, 1400);
    var pause = (Math.random() * 12 + 0.5).toFixed(2);
    var concurrent = (Math.random() * 5 + 0.3).toFixed(2);
    var remark = (Math.random() * 1.5 + 0.1).toFixed(2);
    var cleanup = (Math.random() * 0.8 + 0.05).toFixed(2);

    var lines = [
      { delay: 0,    text: '', type: 'blank' },
      { delay: 300,  text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ') Pause Young (' + cause + ')', type: 'gc' },
      { delay: 900,  text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ')   ' + collector + ': ' + before + 'M->' + heapUsed + 'M(' + heapMax + 'M)', type: 'gc' },
      { delay: 1400, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ')   Collected: ' + reclaimed + 'M reclaimed', type: rand(0, 3) === 0 ? 'gc-error' : 'gc' },
      { delay: 1900, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ')   Pause: ' + pause + 'ms', type: parseFloat(pause) > 8 ? 'warn' : 'gc' },
      { delay: 2500, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ') Concurrent Mark \u2014 ' + concurrent + 'ms', type: 'gc' },
      { delay: 3000, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ') Pause Remark \u2014 ' + remark + 'ms', type: 'gc' },
      { delay: 3400, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ') Concurrent Cleanup \u2014 ' + cleanup + 'ms', type: 'gc' },
      { delay: 3900, text: '[' + ts() + '] [info ] [heap] Heap: ' + heapUsed + 'M / ' + heapMax + 'M', type: 'info' }
    ];

    // Occasionally inject interesting events
    if (rand(0, 4) === 0) {
      lines.push({ delay: 4300, text: '[' + ts() + '] [warn ] [gc  ] GC(' + gcNum + ') To-space exhausted \u2014 promotion failed', type: 'warn' });
    }
    if (rand(0, 6) === 0) {
      lines.push({ delay: 4300, text: '[' + ts() + '] [info ] [gc  ] GC(' + gcNum + ') Initiating Full GC (heap occupancy > 45%)', type: 'error' });
    }

    gcNum++;

    var cycleLength = 4800 + rand(0, 2000);

    lines.forEach(function(line) {
      setTimeout(function() { appendLine(line.text, line.type); }, line.delay);
    });

    setTimeout(nextCycle, cycleLength);
  }

  // Start infinite loop after intro finishes
  setTimeout(nextCycle, 11500);
})();
