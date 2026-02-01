(function() {
  var output = document.getElementById('bytecode-output');
  if (!output) return;

  var path = window.location.pathname;

  var colorMap = {
    'comment': '#888',
    'header': '#c678dd',
    'addr': '#888',
    'inst': '#abb2bf',
    'reg': '#61afef',
    'call': '#98c379',
    'error': '#e06c75',
    'label': '#e5c07b',
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

  function hex(n, pad) {
    var s = n.toString(16);
    while (s.length < (pad || 0)) s = '0' + s;
    return s;
  }

  // --- x86_64 building blocks ---
  var regs64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
  var regs32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d'];

  var methods = [
    'RequestDispatcher::resolve', 'PageResolver::loadPage', 'ContentLoader::read',
    'RouteRegistry::matchPath', 'BlogServlet::doGet', 'CacheManager::lookup',
    'TemplateEngine::render', 'MarkdownProcessor::compile', 'IndexBuilder::build',
    'TagRegistry::search', 'SessionHandler::validate', 'AuthFilter::filter',
    'SearchIndex::query', 'FeedBuilder::generate', 'AssetPipeline::transform',
    'MetricsCollector::record', 'SitemapGenerator::emit', 'CommentHandler::process',
    'PageNotFoundException::<init>', 'ContentResolver::resolveMarkdown'
  ];

  var jvmStubs = [
    'SharedRuntime::resolve_static_call', 'InterpreterRuntime::throw_PageNotFoundException',
    'CompileBroker::compile_method', 'Runtime1::counter_overflow',
    'SharedRuntime::resolve_virtual_call', 'OptoRuntime::new_instance_C',
    'SharedRuntime::handle_wrong_method', 'Runtime1::patch_code',
    'G1BarrierSetRuntime::write_ref_field_post_entry', 'SharedRuntime::complete_monitor_locking_C',
    'StubRoutines::catch_exception', 'OptoRuntime::rethrow_stub',
    'SharedRuntime::throw_NullPointerException_at_call', 'JavaThread::check_safepoint_and_suspend_for_native_trans'
  ];

  var addr = 0x00007f4a60000000 + rand(0, 0xffffff);

  function nextAddr(step) {
    addr += step || rand(1, 8);
    return '0x' + hex(addr, 12);
  }

  // --- Generate a compiled method block ---
  function generateBlock() {
    var lines = [];
    var method = pick(methods);
    var compileId = rand(100, 9999);

    lines.push({ text: '', type: 'blank' });
    lines.push({ html: '<span style="color:#888">============================= C2-compiled nmethod =============================</span>', type: 'html' });
    lines.push({ html: '<span style="color:#c678dd">Compiled method (c2)</span>  <span style="color:#888">' + compileId + '</span>  <span style="color:#e5c07b">io.github.blog.' + method + '</span>', type: 'html' });
    lines.push({ html: '<span style="color:#888"> total in heap  [' + nextAddr(64) + ',' + nextAddr(rand(200, 800)) + '] = ' + rand(400, 2400) + '</span>', type: 'html' });
    lines.push({ html: '<span style="color:#888"> relocation     [' + nextAddr(8) + ',' + nextAddr(rand(40, 120)) + '] = ' + rand(40, 200) + '</span>', type: 'html' });
    lines.push({ html: '<span style="color:#888"> main code      [' + nextAddr(8) + ',' + nextAddr(rand(100, 500)) + '] = ' + rand(120, 800) + '</span>', type: 'html' });
    lines.push({ text: '', type: 'blank' });
    lines.push({ html: '<span style="color:#888">[Disassembly]</span>', type: 'html' });

    var numInstructions = rand(15, 40);
    for (var i = 0; i < numInstructions; i++) {
      var instruction = generateInstruction();
      lines.push(instruction);

      // Occasionally insert 404-related commentary
      if (rand(0, 15) === 0) {
        lines.push({ html: '  <span style="color:#e06c75;font-weight:bold">' + nextAddr(rand(1, 5)) + '</span>: <span style="color:#e06c75">call   ' + nextAddr(rand(100, 5000)) + '</span>  <span style="color:#e06c75">; InterpreterRuntime::throw_PageNotFoundException</span>', type: 'html' });
        lines.push({ html: '  <span style="color:#888">                                              </span><span style="color:#e06c75">; "' + path + '"</span>', type: 'html' });
      }

      // Occasionally insert safepoint or stub call
      if (rand(0, 10) === 0) {
        lines.push({ html: '  <span style="color:#888">' + nextAddr(rand(1, 5)) + '</span>: <span style="color:#abb2bf">call   ' + nextAddr(rand(100, 5000)) + '</span>  <span style="color:#98c379">; ' + pick(jvmStubs) + '</span>', type: 'html' });
        lines.push({ html: '  <span style="color:#888">                                              ; {runtime_call}</span>', type: 'html' });
      }
    }

    lines.push({ text: '', type: 'blank' });
    lines.push({ html: '<span style="color:#888">[Stub Code]</span>', type: 'html' });
    lines.push({ html: '  <span style="color:#888">' + nextAddr(16) + '</span>: <span style="color:#abb2bf">jmp    ' + nextAddr(rand(100, 3000)) + '</span>  <span style="color:#98c379">; StubRoutines::catch_exception</span>', type: 'html' });
    lines.push({ html: '  <span style="color:#888">' + nextAddr(5) + '</span>: <span style="color:#abb2bf">hlt</span>', type: 'html' });

    return lines;
  }

  function generateInstruction() {
    var a = nextAddr(rand(1, 7));
    var ops = [
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">push   </span><span style="color:#61afef">' + r + '</span>', type: 'html' }; },
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">pop    </span><span style="color:#61afef">' + r + '</span>', type: 'html' }; },
      function() { var r1 = pick(regs64); var r2 = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">mov    </span><span style="color:#61afef">' + r1 + '</span>,<span style="color:#61afef">' + r2 + '</span>', type: 'html' }; },
      function() { var r = pick(regs64); var off = rand(-128, 256); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">mov    </span><span style="color:#61afef">' + r + '</span>,QWORD PTR [<span style="color:#61afef">rbp</span>' + (off >= 0 ? '+' : '') + '0x' + hex(Math.abs(off), 2) + ']', type: 'html' }; },
      function() { var r = pick(regs64); var off = rand(0, 128); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">mov    </span>QWORD PTR [<span style="color:#61afef">' + pick(regs64) + '</span>+0x' + hex(off, 2) + '],<span style="color:#61afef">' + r + '</span>', type: 'html' }; },
      function() { var r1 = pick(regs64); var r2 = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">cmp    </span><span style="color:#61afef">' + r1 + '</span>,<span style="color:#61afef">' + r2 + '</span>', type: 'html' }; },
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">test   </span><span style="color:#61afef">' + r + '</span>,<span style="color:#61afef">' + r + '</span>', type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">' + pick(['je', 'jne', 'jl', 'jg', 'jle', 'jge', 'ja', 'jb']) + '     ' + nextAddr(rand(10, 200)) + '</span>', type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">jmp    ' + nextAddr(rand(10, 500)) + '</span>', type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">call   ' + nextAddr(rand(100, 5000)) + '</span>  <span style="color:#98c379">; io.github.blog.' + pick(methods) + '</span>', type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">nop</span>', type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">ret</span>', type: 'html' }; },
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">lea    </span><span style="color:#61afef">' + r + '</span>,[<span style="color:#61afef">rip</span>+0x' + hex(rand(16, 65535), 4) + ']', type: 'html' }; },
      function() { var r1 = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">add    </span><span style="color:#61afef">' + r1 + '</span>,0x' + hex(rand(1, 255), 2), type: 'html' }; },
      function() { var r1 = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">sub    </span><span style="color:#61afef">' + r1 + '</span>,0x' + hex(rand(1, 255), 2), type: 'html' }; },
      function() { var r1 = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">xor    </span><span style="color:#61afef">' + r1 + '</span>,<span style="color:#61afef">' + r1 + '</span>', type: 'html' }; },
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">shl    </span><span style="color:#61afef">' + r + '</span>,0x' + hex(rand(1, 5), 1), type: 'html' }; },
      function() { var r = pick(regs64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">imul   </span><span style="color:#61afef">' + r + '</span>,<span style="color:#61afef">' + pick(regs64) + '</span>,0x' + hex(rand(1, 255), 2), type: 'html' }; },
      function() { return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">movabs </span><span style="color:#61afef">' + pick(regs64) + '</span>,0x' + hex(rand(0x7f0000000000, 0x7fffffffffff), 12), type: 'html' }; },
      function() { var r = pick(regs64); var off = rand(8, 64); return { html: '  <span style="color:#888">' + a + '</span>: <span style="color:#abb2bf">cmp    </span>DWORD PTR [<span style="color:#61afef">' + r + '</span>+0x' + hex(off, 2) + '],0x' + hex(rand(0, 255), 2) + '  <span style="color:#888">; oop null check</span>', type: 'html' }; },
    ];
    return pick(ops)();
  }

  // --- Initial header ---
  var intro = [
    { delay: 0,    html: '<span style="color:#888">Decoding compiled method ' + nextAddr(64) + ':</span>', type: 'html' },
    { delay: 300,  html: '<span style="color:#888">Code:</span>', type: 'html' },
    { delay: 500,  html: '<span style="color:#888">[Entry Point]</span>', type: 'html' },
    { delay: 700,  html: '<span style="color:#888">[Verified Entry Point]</span>', type: 'html' },
    { delay: 900,  html: '<span style="color:#888">[Constants]</span>', type: 'html' },
    { delay: 1100, html: '<span style="color:#888">  # {method} {' + nextAddr(32) + '} \'resolve\' \'(Ljava/lang/String;)Lio/github/blog/content/Page;\' in \'io/github/blog/router/RequestDispatcher\'</span>', type: 'html' },
    { delay: 1400, html: '<span style="color:#888">  # parm0:    rsi:rsi   = \'java/lang/String\'</span>', type: 'html' },
    { delay: 1600, html: '<span style="color:#888">  #           [sp+0x50]  (sp of caller)</span>', type: 'html' },
  ];

  intro.forEach(function(line) {
    setTimeout(function() { appendLine(line.html, 'html'); }, line.delay);
  });

  // --- Infinite block generation ---
  function emitBlock() {
    var lines = generateBlock();
    var baseDelay = 0;

    lines.forEach(function(line, i) {
      var delay = baseDelay + i * rand(60, 180);
      setTimeout(function() {
        if (line.type === 'html') {
          appendLine(line.html, 'html');
        } else {
          appendLine(line.text, line.type);
        }
      }, delay);
    });

    var totalDelay = lines.length * 150 + rand(800, 2000);
    setTimeout(emitBlock, totalDelay);
  }

  setTimeout(emitBlock, 2200);
})();
