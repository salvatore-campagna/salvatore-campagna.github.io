(function() {
  var output = document.getElementById('bytecode-output');
  if (!output) return;

  var path = window.location.pathname;

  var colorMap = {
    'comment': '#888',
    'keyword': '#c678dd',
    'type': '#61afef',
    'class': '#e5c07b',
    'method': '#98c379',
    'error': '#e06c75',
    'label': '#abb2bf',
    'string': '#e5c07b',
    'blank': 'transparent'
  };

  function appendLine(text, type) {
    var div = document.createElement('div');
    div.className = 'line';
    div.style.animationDelay = '0s';

    if (type === 'blank') {
      div.innerHTML = '\u00a0';
    } else if (type === 'html') {
      var prev = output.querySelector('.cursor');
      if (prev) prev.parentNode.removeChild(prev);
      div.innerHTML = text + '<span class="cursor"></span>';
      output.appendChild(div);
      output.scrollTop = output.scrollHeight;
      while (output.children.length > 200) output.removeChild(output.firstChild);
      return;
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
    while (output.children.length > 200) output.removeChild(output.firstChild);
  }

  function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function pick(arr) { return arr[rand(0, arr.length - 1)]; }

  // --- Bytecode building blocks ---
  var packages = [
    'io/github/blog/router', 'io/github/blog/servlet', 'io/github/blog/content',
    'io/github/blog/cache', 'io/github/blog/index', 'io/github/blog/config',
    'io/github/blog/security', 'io/github/blog/template', 'io/github/blog/analytics',
    'javax/servlet/http', 'org/eclipse/jetty/server', 'java/util/concurrent',
    'java/lang/invoke', 'java/util/stream', 'java/nio/file'
  ];

  var classes = [
    'RequestDispatcher', 'PageResolver', 'ContentLoader', 'TemplateEngine',
    'CacheManager', 'RouteRegistry', 'SessionHandler', 'BlogServlet',
    'MarkdownProcessor', 'IndexBuilder', 'TagRegistry', 'PageNotFoundException',
    'AuthFilter', 'RateLimiter', 'MetricsCollector', 'SearchIndex',
    'SitemapGenerator', 'FeedBuilder', 'CommentHandler', 'AssetPipeline'
  ];

  var methods = [
    'resolve', 'dispatch', 'loadPage', 'render', 'lookup', 'matchPath',
    'doGet', 'doPost', 'handleRequest', 'forward', 'service', 'init',
    'destroy', 'filter', 'process', 'compile', 'transform', 'validate',
    'serialize', 'parse', 'index', 'search', 'build', 'generate',
    'flush', 'close', 'open', 'read', 'write', 'execute'
  ];

  var descriptors = [
    'Ljava/lang/String;', 'Ljava/lang/Object;', 'Ljava/util/Map;',
    'Ljava/util/List;', 'Ljava/util/Optional;', 'I', 'J', 'Z', 'V',
    'Ljava/io/InputStream;', 'Ljava/nio/ByteBuffer;', '[B',
    'Ljava/util/concurrent/Future;', 'Ljava/util/function/Function;'
  ];

  var exceptions = [
    'PageNotFoundException', 'NullPointerException', 'IllegalStateException',
    'ClassCastException', 'ArrayIndexOutOfBoundsException', 'IOException',
    'ConcurrentModificationException', 'StackOverflowError',
    'OutOfMemoryError', 'NoSuchElementException', 'UnsupportedOperationException',
    'IllegalArgumentException', 'SecurityException', 'TimeoutException'
  ];

  var labelNum = 0;
  function nextLabel() { return 'L' + (labelNum++); }

  function fullClass() { return pick(packages) + '/' + pick(classes); }

  // --- Generate a random method's bytecode ---
  function generateMethod() {
    var lines = [];
    var cls = fullClass();
    var method = pick(methods);
    var retType = pick(descriptors);
    var argCount = rand(0, 3);
    var args = '';
    for (var a = 0; a < argCount; a++) args += pick(descriptors);
    var lineNum = rand(40, 900);
    var maxStack = rand(2, 8);
    var maxLocals = rand(1, maxStack + 2);

    lines.push({ text: '', type: 'blank' });
    lines.push({ text: '  // access flags 0x' + rand(1, 21).toString(16), type: 'comment' });
    lines.push({ text: '  ' + pick(['public', 'private', 'protected']) + ' ' + method + '(' + args + ')' + retType, type: 'keyword' });

    var numInstructions = rand(8, 25);
    for (var i = 0; i < numInstructions; i++) {
      var label = nextLabel();

      if (rand(0, 4) === 0) {
        lines.push({ text: '   ' + label, type: 'label' });
        lines.push({ text: '    LINENUMBER ' + lineNum + ' ' + label, type: 'comment' });
        lineNum += rand(1, 5);
      }

      var instruction = generateInstruction(cls);
      lines.push(instruction);

      // Occasionally insert error-highlighted lines
      if (rand(0, 12) === 0) {
        var exc = pick(exceptions);
        lines.push({ html: '    <span style="color:#e06c75;font-weight:bold">NEW ' + pick(packages) + '/' + exc + '</span>', type: 'html' });
        lines.push({ text: '    DUP', type: 'label' });
        lines.push({ html: '    <span style="color:#e06c75">LDC</span> <span style="color:#e5c07b">"' + path + '"</span>', type: 'html' });
        lines.push({ html: '    <span style="color:#e06c75;font-weight:bold">ATHROW</span>                                  <span style="color:#e06c75">// &lt;--- 404</span>', type: 'html' });
      }
    }

    lines.push({ text: '    ' + pick(['ARETURN', 'IRETURN', 'LRETURN', 'RETURN', 'ATHROW']), type: 'label' });
    lines.push({ text: '  // Max stack: ' + maxStack + ', Max locals: ' + maxLocals, type: 'comment' });

    return lines;
  }

  function generateInstruction(cls) {
    var ops = [
      function() { return { text: '    ALOAD ' + rand(0, 5), type: 'label' }; },
      function() { return { text: '    ILOAD ' + rand(0, 5), type: 'label' }; },
      function() { return { text: '    ASTORE ' + rand(0, 5), type: 'label' }; },
      function() { return { text: '    ISTORE ' + rand(0, 5), type: 'label' }; },
      function() { return { text: '    GETFIELD ' + fullClass() + '.' + pick(methods) + ' : ' + pick(descriptors), type: 'label' }; },
      function() { return { text: '    PUTFIELD ' + fullClass() + '.' + pick(methods) + ' : ' + pick(descriptors), type: 'label' }; },
      function() { return { text: '    INVOKEVIRTUAL ' + fullClass() + '.' + pick(methods) + ' (' + pick(descriptors) + ')' + pick(descriptors), type: 'label' }; },
      function() { return { text: '    INVOKEINTERFACE ' + fullClass() + '.' + pick(methods) + ' (' + pick(descriptors) + ')' + pick(descriptors) + ' (itf)', type: 'label' }; },
      function() { return { text: '    INVOKESTATIC ' + fullClass() + '.' + pick(methods) + ' (' + pick(descriptors) + ')' + pick(descriptors), type: 'label' }; },
      function() { return { text: '    INVOKESPECIAL ' + fullClass() + '.<init> ()V', type: 'label' }; },
      function() { return { text: '    NEW ' + fullClass(), type: 'label' }; },
      function() { return { text: '    CHECKCAST ' + fullClass(), type: 'label' }; },
      function() { return { text: '    INSTANCEOF ' + fullClass(), type: 'label' }; },
      function() { return { text: '    DUP', type: 'label' }; },
      function() { return { text: '    POP', type: 'label' }; },
      function() { return { text: '    SWAP', type: 'label' }; },
      function() { return { text: '    ICONST_' + rand(0, 5), type: 'label' }; },
      function() { return { text: '    BIPUSH ' + rand(-128, 127), type: 'label' }; },
      function() { return { text: '    SIPUSH ' + rand(-32768, 32767), type: 'label' }; },
      function() { return { text: '    IF_ICMPNE L' + rand(0, labelNum + 5), type: 'label' }; },
      function() { return { text: '    IFNONNULL L' + rand(0, labelNum + 5), type: 'label' }; },
      function() { return { text: '    IFNULL L' + rand(0, labelNum + 5), type: 'label' }; },
      function() { return { text: '    GOTO L' + rand(0, labelNum + 5), type: 'label' }; },
      function() { return { text: '    IADD', type: 'label' }; },
      function() { return { text: '    ISUB', type: 'label' }; },
      function() { return { text: '    AALOAD', type: 'label' }; },
      function() { return { text: '    ARRAYLENGTH', type: 'label' }; },
      function() { return { text: '    MONITORENTER', type: 'label' }; },
      function() { return { text: '    MONITOREXIT', type: 'label' }; },
      function() { return { html: '    LDC <span style="color:#e5c07b">"' + pick([path, '404', 'null', 'Page not found', 'unreachable', pick(methods)]) + '"</span>', type: 'html' }; },
    ];
    return pick(ops)();
  }

  // --- Initial class header ---
  var intro = [
    { delay: 0,    text: '// class version 65.0 (Java 21)', type: 'comment' },
    { delay: 200,  text: '// Decompiling: ' + path, type: 'comment' },
    { delay: 500,  text: '// access flags 0x21', type: 'comment' },
    { delay: 700,  text: 'public class io/github/blog/router/RequestDispatcher {', type: 'keyword' },
    { delay: 1000, text: '', type: 'blank' },
    { delay: 1200, text: '  // compiled from: RequestDispatcher.java', type: 'comment' },
    { delay: 1500, text: '', type: 'blank' },
    { delay: 1700, text: '  private Ljava/util/Map; pageCache', type: 'keyword' },
    { delay: 2000, text: '  private Lio/github/blog/content/ContentResolver; resolver', type: 'keyword' },
  ];

  intro.forEach(function(line) {
    setTimeout(function() { appendLine(line.text, line.type); }, line.delay);
  });

  // --- Infinite method generation ---
  function emitMethod() {
    var lines = generateMethod();
    var baseDelay = 0;

    lines.forEach(function(line, i) {
      var delay = baseDelay + i * rand(80, 250);
      setTimeout(function() {
        if (line.type === 'html') {
          appendLine(line.html, 'html');
        } else {
          appendLine(line.text, line.type);
        }
      }, delay);
    });

    var totalDelay = lines.length * 200 + rand(500, 1500);
    setTimeout(emitMethod, totalDelay);
  }

  setTimeout(emitMethod, 2500);
})();
