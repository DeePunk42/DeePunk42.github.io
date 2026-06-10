import hljs from 'highlight.js/lib/core';
import c from 'highlight.js/lib/languages/c';
import cpp from 'highlight.js/lib/languages/cpp';
import python from 'highlight.js/lib/languages/python';
import x86asm from 'highlight.js/lib/languages/x86asm';
import bash from 'highlight.js/lib/languages/bash';

hljs.registerLanguage('c', c);
hljs.registerLanguage('cpp', cpp);
hljs.registerLanguage('python', python);
hljs.registerLanguage('x86asm', x86asm);
hljs.registerLanguage('bash', bash);

window.hljs = hljs;

if (document.readyState !== 'loading') {
  hljs.highlightAll();
} else {
  document.addEventListener('DOMContentLoaded', () => hljs.highlightAll());
}
