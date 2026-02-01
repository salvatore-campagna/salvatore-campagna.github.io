(function() {
  var path = window.location.pathname;

  var exceptions = [
    {
      type: 'java.lang.NullPointerException',
      message: 'Cannot invoke "Page.render()" because "this.page" is null',
      trace: [
        'at io.github.blog.content.PageRenderer.render(PageRenderer.java:44)',
        'at io.github.blog.servlet.BlogServlet.doGet(BlogServlet.java:142)',
        'at javax.servlet.http.HttpServlet.service(HttpServlet.java:750)',
        'at org.eclipse.jetty.servlet.ServletHolder.handle(ServletHolder.java:799)',
        'at org.eclipse.jetty.server.Server.handle(Server.java:524)',
        '... 18 more'
      ]
    },
    {
      type: 'java.lang.ClassNotFoundException',
      message: path.replace(/\//g, '.').replace(/^\./, '').replace(/\.$/, ''),
      trace: [
        'at java.base/jdk.internal.loader.BuiltinClassLoader.loadClass(BuiltinClassLoader.java:641)',
        'at java.base/jdk.internal.loader.ClassLoaders$AppClassLoader.loadClass(ClassLoaders.java:188)',
        'at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:525)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.servlet.BlogServlet.doGet(BlogServlet.java:142)',
        '... 22 more'
      ]
    },
    {
      type: 'java.lang.ArrayIndexOutOfBoundsException',
      message: 'Index 404 out of bounds for length 2',
      trace: [
        'at io.github.blog.content.PostIndex.getPost(PostIndex.java:67)',
        'at io.github.blog.router.RouteRegistry.matchPath(RouteRegistry.java:156)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.servlet.BlogServlet.doGet(BlogServlet.java:142)',
        'at javax.servlet.http.HttpServlet.service(HttpServlet.java:750)',
        'at org.eclipse.jetty.servlet.ServletHolder.handle(ServletHolder.java:799)',
        '... 16 more'
      ]
    },
    {
      type: 'java.util.NoSuchElementException',
      message: 'No page found for path: ' + path,
      trace: [
        'at java.base/java.util.Optional.orElseThrow(Optional.java:403)',
        'at io.github.blog.content.ContentResolver.loadPage(ContentResolver.java:87)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.router.RequestDispatcher.forward(RequestDispatcher.java:389)',
        'at io.github.blog.servlet.BlogServlet.doGet(BlogServlet.java:142)',
        'at javax.servlet.http.HttpServlet.service(HttpServlet.java:750)',
        'at org.eclipse.jetty.server.Server.handle(Server.java:524)',
        '... 20 more'
      ]
    },
    {
      type: 'java.net.UnknownHostException',
      message: path + ': Name or service not known',
      trace: [
        'at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:572)',
        'at java.base/java.net.Socket.connect(Socket.java:751)',
        'at io.github.blog.content.ContentResolver.fetchRemote(ContentResolver.java:112)',
        'at io.github.blog.content.ContentResolver.loadPage(ContentResolver.java:87)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        '... 19 more'
      ]
    },
    {
      type: 'java.lang.StackOverflowError',
      message: 'Redirect loop detected',
      trace: [
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.router.RequestDispatcher.forward(RequestDispatcher.java:389)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.router.RequestDispatcher.forward(RequestDispatcher.java:389)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.router.RequestDispatcher.forward(RequestDispatcher.java:389)',
        'at io.github.blog.router.RequestDispatcher.resolve(RequestDispatcher.java:404)',
        'at io.github.blog.router.RequestDispatcher.forward(RequestDispatcher.java:389)',
        '... 404 more'
      ]
    }
  ];

  var exc = exceptions[Math.floor(Math.random() * exceptions.length)];
  var output = document.getElementById('random-exception-output');
  if (!output) return;

  var html = '<span style="color:#e06c75;font-weight:bold">Exception</span> ' +
    'in thread <span style="color:#e5c07b">"browser-main"</span> ' +
    '<span style="color:#e06c75;font-weight:bold">' + exc.type + '</span>: ' +
    '<span style="color:#e5c07b">' + exc.message + '</span>\n';

  exc.trace.forEach(function(line) {
    if (line.startsWith('...')) {
      html += '    <span style="color:#555">' + line + '</span>\n';
    } else {
      html += '    <span style="color:#888">at</span> <span style="color:#abb2bf">' + line + '</span>\n';
    }
  });

  output.innerHTML = html;
})();
