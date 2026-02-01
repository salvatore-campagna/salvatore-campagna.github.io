(function() {
  var output = document.getElementById('ascii-output');
  if (!output) return;

  var keywords = [
    'null', 'void', 'throw', 'catch', 'class', 'final',
    'static', 'public', 'import', 'return', 'try{}'
  ];

  var art = [
    '                                                  ',
    '    ##  ##     ####     ##  ##                     ',
    '    ##  ##    ##  ##    ##  ##                     ',
    '    ##  ##   ##    ##   ##  ##                     ',
    '    ######   ##    ##   ######                     ',
    '        ##   ##    ##       ##                     ',
    '        ##    ##  ##        ##                     ',
    '        ##     ####         ##                     ',
    '                                                  '
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
        for (var j = 0; j < kw.length && col < row.length; j++) {
          if (row[col] === '#') {
            line += kw[j];
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
