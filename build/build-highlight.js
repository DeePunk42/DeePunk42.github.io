require('esbuild').buildSync({
  entryPoints: ['build/highlight-entry.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  outfile: 'themes/typo/source/js/highlight.min.js',
});
console.log('Built themes/typo/source/js/highlight.min.js');
