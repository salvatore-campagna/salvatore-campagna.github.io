(function() {
  var output = document.getElementById('bytecode-output');
  if (!output) return;

  var path = window.location.pathname;

  var html =
    '<span style="color:#888">// class version 65.0 (Java 21)</span>\n' +
    '<span style="color:#888">// access flags 0x21</span>\n' +
    '<span style="color:#c678dd">public</span> <span style="color:#c678dd">class</span> <span style="color:#e5c07b">io/github/blog/router/RequestDispatcher</span> {\n' +
    '\n' +
    '  <span style="color:#888">// compiled from: RequestDispatcher.java</span>\n' +
    '\n' +
    '  <span style="color:#888">// access flags 0x2</span>\n' +
    '  <span style="color:#c678dd">private</span> <span style="color:#61afef">Ljava/util/Map;</span> pageCache\n' +
    '\n' +
    '  <span style="color:#888">// access flags 0x2</span>\n' +
    '  <span style="color:#c678dd">private</span> <span style="color:#61afef">Lio/github/blog/content/ContentResolver;</span> resolver\n' +
    '\n' +
    '  <span style="color:#888">// access flags 0x1</span>\n' +
    '  <span style="color:#c678dd">public</span> <span style="color:#98c379">resolve</span>(<span style="color:#61afef">Ljava/lang/String;</span>)<span style="color:#61afef">Lio/github/blog/content/Page;</span>\n' +
    '   L0\n' +
    '    <span style="color:#888">LINENUMBER 398 L0</span>\n' +
    '    ALOAD 0\n' +
    '    GETFIELD <span style="color:#e5c07b">io/github/blog/router/RequestDispatcher</span>.pageCache : <span style="color:#61afef">Ljava/util/Map;</span>\n' +
    '    ALOAD 1\n' +
    '    INVOKEINTERFACE <span style="color:#61afef">java/util/Map</span>.get (<span style="color:#61afef">Ljava/lang/Object;</span>)<span style="color:#61afef">Ljava/lang/Object;</span> (itf)\n' +
    '    CHECKCAST <span style="color:#61afef">io/github/blog/content/Page</span>\n' +
    '    ASTORE 2\n' +
    '   L1\n' +
    '    <span style="color:#888">LINENUMBER 401 L1</span>\n' +
    '    ALOAD 2\n' +
    '    IFNONNULL L2\n' +
    '   L3\n' +
    '    <span style="color:#888">LINENUMBER 402 L3</span>\n' +
    '    ALOAD 0\n' +
    '    GETFIELD <span style="color:#e5c07b">io/github/blog/router/RequestDispatcher</span>.resolver : <span style="color:#61afef">Lio/github/blog/content/ContentResolver;</span>\n' +
    '    ALOAD 1\n' +
    '    INVOKEVIRTUAL <span style="color:#61afef">io/github/blog/content/ContentResolver</span>.loadPage (<span style="color:#61afef">Ljava/lang/String;</span>)<span style="color:#61afef">Ljava/util/Optional;</span>\n' +
    '    ASTORE 2\n' +
    '   L4\n' +
    '    <span style="color:#888">LINENUMBER 403 L4</span>\n' +
    '    ALOAD 2\n' +
    '    INVOKEVIRTUAL <span style="color:#61afef">java/util/Optional</span>.isPresent ()<span style="color:#61afef">Z</span>\n' +
    '    IFNE L2\n' +
    '   <span style="color:#e06c75;font-weight:bold">L5</span>\n' +
    '    <span style="color:#e06c75;font-weight:bold">LINENUMBER 404 L5</span>                          <span style="color:#e06c75">// &lt;--- YOU ARE HERE</span>\n' +
    '    <span style="color:#e06c75;font-weight:bold">NEW io/github/blog/PageNotFoundException</span>\n' +
    '    DUP\n' +
    '    <span style="color:#e06c75">LDC</span> <span style="color:#e5c07b">"' + path + '"</span>\n' +
    '    <span style="color:#e06c75;font-weight:bold">INVOKESPECIAL io/github/blog/PageNotFoundException.&lt;init&gt;</span> (<span style="color:#61afef">Ljava/lang/String;</span>)<span style="color:#61afef">V</span>\n' +
    '    <span style="color:#e06c75;font-weight:bold">ATHROW</span>\n' +
    '   L2\n' +
    '    <span style="color:#888">LINENUMBER 408 L2</span>\n' +
    '   FRAME APPEND [<span style="color:#61afef">io/github/blog/content/Page</span>]\n' +
    '    ALOAD 2\n' +
    '    ARETURN\n' +
    '\n' +
    '  <span style="color:#888">// Local variable table:</span>\n' +
    '  <span style="color:#888">//   Slot  Name           Descriptor</span>\n' +
    '  <span style="color:#888">//   0     this           Lio/github/blog/router/RequestDispatcher;</span>\n' +
    '  <span style="color:#888">//   1     path           Ljava/lang/String;                          // = "' + path + '"</span>\n' +
    '  <span style="color:#888">//   2     cachedPage     Lio/github/blog/content/Page;               // = null</span>\n' +
    '\n' +
    '  <span style="color:#888">// Max stack: 3, Max locals: 3</span>\n' +
    '}\n';

  output.innerHTML = html;
})();
