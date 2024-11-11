# hook-tkinterdnd2.py
import os
import sys
import tkinterdnd2
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, get_package_paths

# Get base path of tkinterdnd2
dnd_path = os.path.dirname(tkinterdnd2.__file__)

# Collect all data files
datas = collect_data_files('tkinterdnd2')

# Add tkdnd directory specifically
tkdnd_path = os.path.join(dnd_path, 'tkdnd')
if os.path.exists(tkdnd_path):
    datas.append((tkdnd_path, 'tkinterdnd2/tkdnd'))

# Add all DLL files
if sys.platform.startswith('win'):
    dlls = []
    for root, dirs, files in os.walk(dnd_path):
        for file in files:
            if file.endswith('.dll'):
                dlls.append((os.path.join(root, file), '.'))
    datas.extend(dlls)

# Collect all submodules
hiddenimports = collect_submodules('tkinterdnd2')