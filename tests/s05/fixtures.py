"""Finite deterministic source corpus. Author: Antonio Clim. Never execute sources."""
from __future__ import annotations


def branching(complexity):
    return ('def gen_example(x):\n' + ''.join('    if x == %d: return %d\n' % (i,i) for i in range(complexity-1)) + '    return x\n').encode()


def cases():
    return [
        ('empty',b'','python'),
        ('no-callable',b'x = 1\n','python'),
        ('syntax-error',b'def broken(:\n','python'),
        ('plain-text',b'Synthetic prose.\n','text'),
        ('markdown',b'# Title\n\n~~~\nx\n~~~\n','markdown'),
        ('markdown-unclosed',b'~~~\nx\n','markdown'),
        ('below',branching(8),'python'),
        ('lower-plus-one',branching(9),'python'),
        ('nominal',branching(10),'python'),
        ('nominal-plus-one',branching(11),'python'),
        ('upper',branching(12),'python'),
        ('above',branching(13),'python'),
        ('above-conservative',branching(19),'python'),
        ('long-span',b'def gen_long(x):\n'+b'    x += 1\n'*125+b'    return x\n','python'),
        ('unicode-bom-crlf',b'\xef\xbb\xbf'+ 'def gen_șir(x):\r\n    return "漢字"\r\n'.encode(),'python'),
        ('hostile-markup',b'# </script><img src="https://invalid.example/x" onerror="globalThis.injected=true">\n'+branching(13),'python'),
        ('sensitive-literal',b'def confidential_name(x):\n    return "SECRET_LITERAL_5ac7"\n','python'),
        ('directional', '# \u202eevil\u202c\n'.encode()+branching(13),'python'),
    ]
