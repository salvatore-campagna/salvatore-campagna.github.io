(function() {
  var output = document.getElementById('ascii-output');
  if (!output) return;

  var keywords = [
    'null', 'void', 'throw', 'catch', 'class', 'final', 'try{}',
    'static', 'public', 'import', 'return', 'break', 'super',
    'synchronized', 'volatile', 'abstract', 'extends', 'implements',
    'private', 'protected', 'interface', 'throws', 'finally'
  ];

  var art = [
    '                                                                                          ',
    '   ##          ##      ######      ##          ##                                          ',
    '   ##          ##     ##    ##     ##          ##                                          ',
    '   ##          ##    ##      ##    ##          ##                                          ',
    '   ##          ##    ##      ##    ##          ##                                          ',
    '   ##    ##    ##    ##      ##    ##    ##    ##                                          ',
    '   ##    ##    ##    ##      ##    ##    ##    ##                                          ',
    '   ########    ##    ##      ##    ########    ##                                          ',
    '   ########    ##    ##      ##    ########    ##                                          ',
    '         ##    ##    ##      ##          ##    ##                                          ',
    '         ##    ##    ##      ##          ##    ##                                          ',
    '         ##    ##    ##      ##          ##    ##                                          ',
    '         ##    ##     ##    ##           ##    ##                                          ',
    '         ##    ##      ######            ##    ##                                          ',
    '                                                                                          ',
    '                                                                                          ',
    '      ####       ####      #####     ########                                             ',
    '     ##  ##     ##  ##     ##   ##   ##                                                   ',
    '    ##    ##   ##    ##    ##    ##  ##                                                    ',
    '    ##    ##   ##    ##    ##    ##  ########                                              ',
    '    ########   ##    ##    ##    ##  ##                                                    ',
    '    ##    ##   ##    ##    ##   ##   ##                                                    ',
    '    ##    ##    ##  ##     #####     ##                                                    ',
    '    ##    ##     ####      ##        ########                                              ',
    '                                                                                          '
  ];

  var result = '';
  var ki = 0;

  art.forEach(function(row) {
    var line = '';
    var col = 0;
    while (col < row.length) {
      if (row[col] === '#') {
        var kw = keywords[ki % keywords.length];
        ki++;
        var j = 0;
        while (j < kw.length && col < row.length) {
          if (row[col] === '#') {
            line += kw[j];
            j++;
          } else {
            line += ' ';
          }
          col++;
        }
      } else {
        line += ' ';
        col++;
      }
    }
    result += line + '\n';
  });

  output.textContent = result;
})();
