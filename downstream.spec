# -*- mode: python -*-
import os

a = Analysis(['downstream.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
a.datas += [('ca-bundle.crt',os.path.join('data','ca-bundle.crt'),'DATA')]
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='downstream.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True )
