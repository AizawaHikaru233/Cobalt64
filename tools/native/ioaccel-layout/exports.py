#!/usr/bin/env python3
"""exports.py - the exported-symbol universe of the four binaries the model reads.

    load() -> set of every symbol name exported by FAMILY / IOGF / BOOT_KC / SYS_KC, from `nm -gU <binary>`
              (the very same command and the same parsing gates/layout_gate_host.py::sym_addr_table() uses),
              cached in exports_cache.txt next to this file.

The consumers: gates/gate_link.py gate B resolves the LINKED kext's undefined symbols against this set
("B %d undefined symbols, %d not exported by family/kernel/IOGraphicsFamily"), and model.py marks a vtable
slot whose target is in no export table as NON-EXPORTED (the slots Navi48Accel.cpp has to forward).
A stale cache is impossible: every source's size+mtime is stored in the cache header and re-checked.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, 'exports_cache.txt')
CACHE_VERSION = 'v1'

sys.path.insert(0, HERE)
import kcmod


def sources():
    """(path, label) of the binaries whose exports count, in the model's resolution order.

    IOGF is universal, so the x86_64 slice is used (kcmod.thinned_x86_64, via lipo); the paths come from
    kcmod, so exports.py and model.py can never disagree about which binary is which.
    """
    return [(kcmod.FAMILY, 'family'), (kcmod.thinned_x86_64(kcmod.IOGF), 'iographics'),
            (kcmod.BOOT_KC, 'bootkc'), (kcmod.SYS_KC, 'syskcs')]


def nm_exports(path):
    """the exported names of one binary: `nm -gU` (= global, defined), same line filter as the host twin."""
    out = subprocess.run(['nm', '-gU', path], capture_output=True, text=True).stdout
    names = []
    for line in out.splitlines():
        q = line.split(' ', 2)
        if len(q) == 3 and q[0] and all(c in '0123456789abcdef' for c in q[0]):
            names.append(q[2])
    return names


def _fingerprint(srcs):
    lines = []
    for path, label in srcs:
        try:
            st = os.stat(path)
            lines.append('# %s %s %d %d' % (label, path, st.st_size, int(st.st_mtime)))
        except OSError:
            lines.append('# %s %s MISSING 0' % (label, path))
    return lines


def _read_cache(srcs):
    try:
        with open(CACHE) as f:
            text = f.read()
    except OSError:
        return None
    lines = text.splitlines()
    if not lines or lines[0] != '# exports.py cache ' + CACHE_VERSION:
        return None
    want = _fingerprint(srcs)
    have = [l for l in lines[1:len(want) + 1]]
    if have != want:
        return None
    return set(l for l in lines[len(want) + 1:] if l)


def _write_cache(srcs, names):
    with open(CACHE, 'w') as f:
        f.write('# exports.py cache %s\n' % CACHE_VERSION)
        f.write('\n'.join(_fingerprint(srcs)) + '\n')
        f.write('\n'.join(sorted(names)) + '\n')


def load(force=False):
    """the set of every exported symbol name of the four binaries (cached in exports_cache.txt)."""
    srcs = sources()
    missing = [p for p, _ in srcs if not os.path.exists(p)]
    if missing:
        raise RuntimeError('exports.py: input binary missing: ' + ', '.join(missing))
    if not force:
        cached = _read_cache(srcs)
        if cached is not None:
            return cached
    names = set()
    for path, _label in srcs:
        names.update(nm_exports(path))
    try:
        _write_cache(srcs, names)
    except OSError as e:
        print('exports.py: cannot write %s (%s)' % (CACHE, e), file=sys.stderr)
    return names


def refresh():
    """drop the cache file and rebuild it."""
    return load(force=True)


def main():
    srcs = sources()
    print('# exports.py - exported symbols of the model inputs')
    for path, label in srcs:
        st = os.stat(path) if os.path.exists(path) else None
        print('#   %-11s %-96s %s' % (label, path, '%d bytes' % st.st_size if st else 'MISSING'))
    names = load(force=True)
    print('# %d exported symbol names, cached in %s' % (len(names), CACHE))
    return 0


if __name__ == '__main__':
    sys.exit(main())
