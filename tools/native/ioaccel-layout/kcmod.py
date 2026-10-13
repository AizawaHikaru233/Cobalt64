#!/usr/bin/env python3
"""kcmod.py - the Mach-O access layer of the IOAccelFamily2 vtable model (tools/native/ioaccel-layout).

Constants (the four binaries the model and gates/layout_gate_host.py read):

    FAMILY   IOAcceleratorFamily2.kext  (x86_64 kext bundle, linked at 0)      level 1
    IOGF     IOGraphicsFamily.kext      (universal fat: x86_64 + arm64e)       level 1   <- needs a lipo slice
    BOOT_KC  /System/Library/KernelCollections/BootKernelExtensions.kc         level 0
    SYS_KC   /System/Library/KernelCollections/SystemKernelExtensions.kc       level 1

A kext is linked at base 0, so a relocation address IS a vm address.  Reading a C++ vtable of a
classic Mach-O (this is what refs/nvidia-macos-driver/tools/vtdump.py does, 61 lines):

  * a slot covered by an EXTERNAL relocation holds a reference to the symbol named there (usually an
    import: __cxa_pure_virtual, an IOService/OSObject method, a method of another kext);
  * any other slot holds the target's vm address, which the symbol table names (possibly a LOCAL,
    non-exported symbol: that is exactly the set the leaf kext must forward with a naked tail jump).

Helpers here: LC_SYMTAB/LC_DYSYMTAB, the external/local relocation tables, address -> symbol name,
`nm -gU` exports (the same parser gates/layout_gate_host.py::sym_addr_table() uses), c++filt, and the
OSMetaClass super-class map (`__ZN<len><Class>10superClassE` is an external reference to the base
class's `gMetaClass`, which gives the EXACT direct base class of every OSMetaClass-based class).
"""

import bisect
import collections
import os
import re
import struct
import subprocess
import sys
import tempfile

__all__ = ['FAMILY', 'IOGF', 'BOOT_KC', 'SYS_KC', 'MachO', 'load', 'nm_table', 'demangle', 'split_symbol',
           'thinned_x86_64', 'kdk_root', 'check_inputs']

# -------------------------------------------------------------------------------------------------------------------------------
# the four inputs.  The KDK is versioned (KDK_<os>_<build>.kdk); the paths below are the ones of the running
# 26.6.2 / 25G83 build and are what model.py and exports.py use.  _first_existing()/kdk_root() only step in when a
# KDK is replaced: they keep both modules on the SAME binary (they both resolve through the constants).
# -------------------------------------------------------------------------------------------------------------------------------
KDK_PATHS = [
    '/Library/Developer/KDKs/KDK_26.6.2_25G83.kdk',
]
_KDK_DIRS = '/Library/Developer/KDKs'


def _newest_kdk():
    """the KDK directory to use when the pinned one is gone: prefer the newest by name."""
    try:
        names = sorted(d for d in os.listdir(_KDK_DIRS) if d.endswith('.kdk'))
    except OSError:
        return None
    return os.path.join(_KDK_DIRS, names[-1]) if names else None


def kdk_root():
    for k in KDK_PATHS:
        if os.path.isdir(k):
            return k
    return _newest_kdk()


def _kdk_binary(rel):
    k = kdk_root()
    if k:
        p = os.path.join(k, rel)
        if os.path.exists(p):
            return p
    return _newest_kdk() and os.path.join(_newest_kdk(), rel) or os.path.join('/nonexistent', rel)


FAMILY = _kdk_binary('System/Library/Extensions/IOAcceleratorFamily2.kext/Contents/MacOS/IOAcceleratorFamily2')
IOGF = _kdk_binary('System/Library/Extensions/IOGraphicsFamily.kext/IOGraphicsFamily')
BOOT_KC = os.path.join('/System/Library/KernelCollections', 'BootKernelExtensions.kc')
SYS_KC = os.path.join('/System/Library/KernelCollections', 'SystemKernelExtensions.kc')


def check_inputs(paths=None):
    """{path: exists} for the inputs, so a caller can fail early with a readable message."""
    return {p: os.path.exists(p) for p in (paths if paths is not None else (FAMILY, IOGF, BOOT_KC, SYS_KC))}


# -------------------------------------------------------------------------------------------------------------------------------
# fat -> thin
# -------------------------------------------------------------------------------------------------------------------------------
_FAT_MAGICS = (0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca)
CPU_TYPE_X86_64 = 0x01000007
_THIN_CACHE = os.path.join(tempfile.gettempdir(), 'ioaccel-layout-thin')


def _fat_slice(data, want=CPU_TYPE_X86_64):
    """the <want> slice of a universal binary, or None (data is returned unchanged when it is not fat)."""
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic not in _FAT_MAGICS:
        return data
    big = magic in (0xcafebabe, 0xcafebabf)
    wide = magic in (0xcafebabf, 0xbfbafeca)
    n = struct.unpack_from('>I', data, 4)[0] if big else struct.unpack_from('<I', data, 4)[0]
    for i in range(n):
        off = 8 + i * (32 if wide else 20)
        if wide:
            cputype = struct.unpack_from('>i', data, off)[0]
            fo, size = struct.unpack_from('>QQ', data, off + 8)
        else:
            cputype, _csub, fo, size, _align = struct.unpack_from('>IIIII', data, off)
        if cputype == want:
            return data[fo:fo + size]
    return None


def thinned_x86_64(path):
    """an x86_64 thin copy of <path> (via lipo -thin x86_64, cached under $TMPDIR); <path> itself when already thin."""
    with open(path, 'rb') as f:
        head = f.read(8)
    if struct.unpack_from('<I', head, 0)[0] not in _FAT_MAGICS:
        return path
    st = os.stat(path)
    out = os.path.join(_THIN_CACHE, os.path.basename(path) + '.x86_64')
    stamp = out + '.stamp'
    want = '%d %d\n' % (st.st_size, int(st.st_mtime))
    try:
        if open(stamp).read() == want and os.path.getsize(out) > 0:
            return out
    except OSError:
        pass
    if not os.path.isdir(_THIN_CACHE):
        os.makedirs(_THIN_CACHE)
    subprocess.check_call(['lipo', '-thin', 'x86_64', '-output', out, path])
    with open(stamp, 'w') as f:
        f.write(want)
    return out


# -------------------------------------------------------------------------------------------------------------------------------
# Mach-O
# -------------------------------------------------------------------------------------------------------------------------------
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
MH_MAGIC_64 = 0xfeedfacf
N_STAB = 0xe0
N_TYPE = 0x0e
N_EXT = 0x01


def split_symbol(name):
    """'__ZTV24IOAccelEventMachineFast2' -> (kind, '24IOAccelEventMachineFast2').

    Mach-O stores C/C++ symbols with one extra leading underscore, so a vtable symbol is the literal
    '__ZTV' + <byte length of the class name> + <class name>.  Mirrors vtdump.py: `cls = n[5:]`.
    """
    if name.startswith('__ZTV'):
        return 'vtable', name[5:]
    if name.startswith('__ZTI'):
        return 'typeinfo', name[5:]
    if name.startswith('__ZTS'):
        return 'name', name[5:]
    return None, name[2:] if name.startswith('__') else name.lstrip('_')


def _meta_class_name(target):
    """'__ZN9IOService10gMetaClassE' -> 'IOService' (a <length><name> pair per component; the member is the
    last one).  Returns None when the symbol is not a metaclass-of-a-class data symbol."""
    m = re.match(r'^__ZN(\d+)(.*)$', target)
    if not m:
        return None
    ln, rest = int(m.group(1)), m.group(2)
    name, rest = rest[:ln], rest[ln:]
    m2 = re.match(r'^(\d+)(gMetaClass|metaClass|MetaClass)E$', rest)
    if not m2 or int(m2.group(1)) != len(m2.group(2)) or len(name) != ln:
        return None
    return name


class MachO(object):
    """a thin 64-bit Mach-O image: segments, symbol table, relocations, vtable reader."""

    def __init__(self, path, thin=True):
        self.path = path
        self.thin_path = thinned_x86_64(path) if thin else path
        with open(self.thin_path, 'rb') as f:
            self.data = f.read()
        d = self.data
        if len(d) < 32 or struct.unpack_from('<I', d, 0)[0] != MH_MAGIC_64:
            raise ValueError('%s is not a thin 64-bit Mach-O (%s)' % (path, self.thin_path))
        self.cputype = struct.unpack_from('<i', d, 4)[0]
        ncmds = struct.unpack_from('<I', d, 16)[0]
        p = 32
        self.segs = []
        symtab = dysymtab = None
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', d, p)
            if cmd == LC_SEGMENT_64:
                segname = d[p + 8:p + 24].split(b'\0')[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, p + 24)
                self.segs.append(dict(name=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize))
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack_from('<IIII', d, p + 8)
            elif cmd == LC_DYSYMTAB:
                dysymtab = struct.unpack_from('<' + 'I' * 18, d, p + 8)
            p += size
        if not symtab or not dysymtab:
            raise ValueError('%s: no LC_SYMTAB/LC_DYSYMTAB' % path)
        symoff, nsyms, stroff, _strsize = symtab
        self.syms = []
        for i in range(nsyms):
            strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', d, symoff + i * 16)
            end = d.index(b'\0', stroff + strx)
            self.syms.append(dict(name=d[stroff + strx:end].decode(errors='replace'), type=n_type,
                                  sect=n_sect, value=n_value))
        # external relocations: <address, info> with r_symbolnum = info & 0xffffff into the symbol table
        self.ext = {}
        extreloff, nextrel = dysymtab[14], dysymtab[15]
        for i in range(nextrel):
            addr, info = struct.unpack_from('<iI', d, extreloff + i * 8)
            self.ext[addr] = self.syms[info & 0xffffff]['name']
        # local relocations: the slot is defined in this image (it holds our own address)
        self.loc = {}
        locreloff, nlocrel = dysymtab[16], dysymtab[17]
        for i in range(nlocrel):
            addr, _info = struct.unpack_from('<iI', d, locreloff + i * 8)
            self.loc[addr] = True
        # address -> name over every DEFINED symbol (locals included), first one wins (vtdump: byaddr.setdefault)
        self.byaddr = {}
        self.names_at = collections.defaultdict(list)
        self.defined = []           # sorted (vmaddr, name)
        for s in self.syms:
            if not s['sect'] or not s['name'] or (s['type'] & N_STAB):
                continue
            self.byaddr.setdefault(s['value'], s['name'])
            self.names_at[s['value']].append(s['name'])
            self.defined.append((s['value'], s['name']))
        self.defined.sort()
        self._addrs = [v for v, _ in self.defined]
        self._vt = None
        self._super = None

    # -- address helpers -------------------------------------------------------
    def file_off(self, va):
        for s in self.segs:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize'] and s['filesize']:
                if va - s['vmaddr'] < s['filesize']:
                    return s['fileoff'] + va - s['vmaddr']
                return None
        return None

    def u64(self, va):
        off = self.file_off(va)
        return struct.unpack_from('<Q', self.data, off)[0] if off is not None else None

    def name_at(self, va):
        """the name of the DEFINED symbol at exactly <va>, or None."""
        j = bisect.bisect_left(self._addrs, va)
        if j < len(self._addrs) and self._addrs[j] == va:
            return self.defined[j][1]
        return None

    def next_defined(self, va):
        """the address of the first defined symbol strictly above <va> (the vtable's end)."""
        j = bisect.bisect_right(self._addrs, va)
        return self.defined[j][0] if j < len(self.defined) else None

    def slot(self, va):
        """what a vtable slot at <va> holds: ('ext', symbol name) | ('addr', target vm address) | ('zero', 0)."""
        if va in self.ext:
            return ('ext', self.ext[va])
        val = self.u64(va)
        if not val:
            return ('zero', 0)
        return ('addr', val)

    # -- tables ----------------------------------------------------------------
    def vtables(self):
        """{mangled class name (with its length prefix): [slot names]}: every __ZTV symbol in the image.

        A vtable starts at `va + 16` (skip offset-to-top and the typeinfo reference) and ends at the next
        defined symbol above it (bounded by va + 8*400); trailing zero slots are dropped (nterm).
        """
        if self._vt is None:
            out = {}
            for va, name in self.defined:
                if not name.startswith('__ZTV'):
                    continue
                end = self.next_defined(va) or (va + 8 * 400)
                if end > va + 8 * 400:
                    end = va + 8 * 400
                out[name[5:]] = [self.slot(a) for a in range(va + 16, end, 8)]
            self._vt = out
        return self._vt

    def rows(self, cls):
        """(vm address, [(slot address, kind, value), ...]) of __ZTV<cls>: <cls> is the PLAIN class name."""
        name = '__ZTV%d%s' % (len(cls), cls)
        va = None
        for s in self.syms:
            if s['name'] == name and s['sect']:
                va = s['value']
                break
        if va is None:
            return None, None
        end = self.next_defined(va) or (va + 8 * 400)
        if end > va + 8 * 400:
            end = va + 8 * 400
        return va, [(a,) + self.slot(a) for a in range(va + 16, end, 8)]

    def super_map(self):
        """{plain class name: plain name of the direct base class} from the OSMetaClass superClass symbol.

        `OSDefineMetaClassAndStructors(C, P)` emits `C::superClass`, a data symbol holding (at load time)
        `&P::gMetaClass`.  In the unlinked kext that data word carries an EXTERNAL relocation to
        `__ZN<len P><P>9(g)MetaClassE`, which names the direct base class exactly.
        """
        if self._super is not None:
            return self._super
        out = {}
        for s in self.syms:
            m = re.match(r'^__ZN\d+(.*)10superClassE$', s['name'])
            if not m or not s['sect']:
                continue
            cls = m.group(1)
            target = None
            if s['value'] in self.ext:
                target = self.ext[s['value']]
            else:
                val = self.u64(s['value'])
                if val:
                    target = self.byaddr.get(val)
            if not target:
                out[cls] = None
                continue
            out[cls] = _meta_class_name(target)
        self._super = out
        return out

_LOADED = {}


def load(path):
    """a cached MachO for <path> (the x86_64 slice of a universal binary)."""
    key = os.path.realpath(path)
    if key not in _LOADED:
        _LOADED[key] = MachO(path)
    return _LOADED[key]


# -------------------------------------------------------------------------------------------------------------------------------
# nm -gU / c++filt
# -------------------------------------------------------------------------------------------------------------------------------
_NM_CACHE = {}


def nm_table(path):
    """{symbol name: vm address} for every exported (global, defined) symbol of <path>, from `nm -gU`.

    The line filter is byte-for-byte the one gates/layout_gate_host.py::sym_addr_table() uses, so a
    (level, address) pair computed here is the pair that host twin expects.
    """
    if path in _NM_CACHE:
        return _NM_CACHE[path]
    out = subprocess.run(['nm', '-gU', path], capture_output=True, text=True).stdout
    tab = {}
    for line in out.splitlines():
        q = line.split(' ', 2)
        if len(q) == 3 and q[0] and all(c in '0123456789abcdef' for c in q[0]):
            tab.setdefault(q[2], int(q[0], 16))
    _NM_CACHE[path] = tab
    return tab


def nm_names(path):
    return list(nm_table(path).keys())


def demangle(names):
    """[names] demangled by /usr/bin/c++filt (one output line per input line)."""
    names = list(names)
    if not names:
        return []
    p = subprocess.run(['c++filt'], input='\n'.join(names), capture_output=True, text=True)
    out = p.stdout.split('\n')
    if len(out) > len(names) and out and out[-1] == '':
        out.pop()
    if len(out) != len(names):                      # never trust a mismatched batch
        return [subprocess.run(['c++filt', n], capture_output=True, text=True).stdout.strip() for n in names]
    return out


if __name__ == '__main__':
    for p, ok in sorted(check_inputs().items()):
        print('%-6s %s' % ('OK' if ok else 'MISSING', p))
    for path in (FAMILY, IOGF):
        if os.path.exists(path):
            m = load(path)
            print('%-40s thin=%s  %d symbols  %d vtables  %d classes with superClass'
                  % (os.path.basename(path), os.path.basename(m.thin_path), len(m.syms),
                     len(m.vtables()), len(m.super_map())))
    sys.exit(0)
