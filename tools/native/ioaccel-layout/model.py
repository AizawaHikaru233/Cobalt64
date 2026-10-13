#!/usr/bin/env python3
"""model.py - build the IOAcceleratorFamily2 vtable model the Navi48Accel aux kext is checked against, and write

    generated/model.json      per class: nslots, nterm, rows[i] = {i, pure, mangled, lvl, va}
    generated/forwarded.json  per class: the slot numbers whose target is NOT exported by
                              IOAcceleratorFamily2 / the Boot KC / the System KC (gate_link.py: the slots our leaf
                              has to forward with a naked tail jump; gate A's override set grows by them)
    generated/slots.json      per class: super + the slots the class introduces/overrides (gen_tramp.py's
                              sig_of()/visible() source of (name, args, cv, owner))
    generated/sizes.json      per class: sizeof(C) and where the number comes from (the runtime layout gate
                              compares OSMetaClass::getClassSize() against it)
    vtables/IOFramebuffer.tsv the IOFramebuffer vtable listing (idx, va, mangled, PURE|real|sdk, level, address,
                              demangled) - what navi48accel/tests/host_test.cpp, plant.sh and gate_plants.sh read

Everything is read from the binaries (kcmod.py); nothing is estimated:

  * a vtable slot is either an EXTERNAL relocation (the slot references the named symbol) or a plain address
    resolved through the symbol table, locals included;
  * `pure` = the target is __cxa_pure_virtual;
  * (lvl, va) = the first hit of the export tables in the order gates/layout_gate_host.py's sym_addr_table()
    uses: (1, FAMILY), (0, BOOT_KC), (1, SYS_KC).  A slot whose target is in none of them is "non-exported":
    our leaf cannot reference it by name, so it goes into forwarded.json and its (lvl, va) is the target's own
    address in the kext (level 1) - the field stays present and non-zero, which gate_compare requires;
  * the direct base class is the EXACT OSMetaClass one (`__ZN<len><Class>10superClassE` carries an external
    reference to the base's `gMetaClass`), not a vtable-prefix heuristic;
  * a signature is c++filt of the slot's symbol.  A PURE slot has no symbol of its own (__cxa_pure_virtual), so
    its declaration is recovered from a concrete subclass that implements it - in the KDK the AppleParavirt*
    classes are exactly those subclasses (AppleParavirtEventMachine implements slots 84-87 of
    IOAccelEventMachineFast2, AppleParavirtResource 58/60-65 of IOAccelResource2, AppleParavirtVidMemory
    43/61/62, AppleParavirt2DContext 360/361, AppleParavirtFramebuffer IOFramebuffer's 8, ...).  That is what
    gen_tramp.py needs: a trampoline leaf overrides precisely the parent's pure slots.  For a class whose
    declaration is public (IOFramebuffer) the SDK header's own spelling wins (kind "sdk");
  * sizeof(C) is MEASURED from C's own OSMetaClass constructor (OSDefineMetaClassAndStructors passes sizeof(C)
    as the classSize argument, the exact field the runtime gate compares), and cross-checked against the two
    constructors C1/C2 and, where one exists, the allocating factory; the RE reference headers are a
    cross-check only, never the source of truth.

Class set: the 14 ROOTS plus the ANCESTOR CLOSURE - every base class the SDK does not declare.  The generated
header can only declare, for each class, the slots that class defines itself; the inherited ones come from the
real base class's declaration, so every model class's `super` must be either a model class or a class the SDK
headers declare (MacKernelSDK: IOKit/IOService.h, libkern/c++/OSObject.h, IOKit/IOUserClient.h,
IOKit/graphics/IOFramebuffer.h, IOKit/graphics/IOGraphicsDevice.h).  IOAccelerator is the exception: the SDK
declares it too (IOKit/graphics/IOAccelerator.h, three static members, no virtual), but the generated header
declares it itself instead of including that stub, so it is the last class of this model.  Its vtable exists
ONLY in IOGraphicsFamily: in IOAcceleratorFamily2 `__ZTV13IOAccelerator` is an UNDEFINED symbol (`U`), so the
rows come from IOGraphicsFamily, and its 266 slots are exactly IOService's (it introduces no virtual).

Nothing outside this directory is written.  Usage: model.py [--check] [--quiet]
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kcmod
import exports

GEN_DIR = os.path.join(HERE, 'generated')
VT_DIR = os.path.join(HERE, 'vtables')
MODEL_JSON = os.path.join(GEN_DIR, 'model.json')
FORWARDED_JSON = os.path.join(GEN_DIR, 'forwarded.json')
SLOTS_JSON = os.path.join(GEN_DIR, 'slots.json')
SIZES_JSON = os.path.join(GEN_DIR, 'sizes.json')

# -------------------------------------------------------------------------------------------------------------------------------
# the classes of the model.  The 13 first are the parents of gates/leaves.py LEAVES; IOAccelEventMachine2 is the
# base of IOAccelEventMachineFast2 and must be a class of slots.json for visible() to walk into it: slots 72/73 of
# the event machine are IOAccelEventMachine2's own and Navi48Accel.cpp pins them as N48_R_IOAccelEventMachine2_72/73.
# The rest of the model is the closure computed in Model.closure().
# -------------------------------------------------------------------------------------------------------------------------------
PARENTS = [
    ('IOGraphicsAccelerator2', 'FAMILY'),
    ('IOAccelEventMachine2', 'FAMILY'),
    ('IOAccelEventMachineFast2', 'FAMILY'),
    ('IOAccelTask', 'FAMILY'),
    ('IOAccelDisplayMachine', 'FAMILY'),
    ('IOAccelSysMemory', 'FAMILY'),
    ('IOAccelVidMemory', 'FAMILY'),
    ('IOAccelResource2', 'FAMILY'),
    ('IOAccel2DContext2', 'FAMILY'),
    ('IOAccelSharedUserClient2', 'FAMILY'),
    ('IOAccelCommandQueue', 'FAMILY'),
    ('IOAccelDisplayPipe', 'FAMILY'),
    ('IOAccelMemoryMap', 'FAMILY'),
    ('IOFramebuffer', 'IOGF'),
]

# the acceptance line of the task (slot counts).  Read by --check ONLY.
ACCEPT_SLOTS = {
    'IOGraphicsAccelerator2': 350, 'IOAccelEventMachine2': 84, 'IOAccelEventMachineFast2': 95,
    'IOAccelTask': 51, 'IOAccelDisplayMachine': 284, 'IOAccelSysMemory': 66, 'IOAccelVidMemory': 69,
    'IOAccelResource2': 79, 'IOAccel2DContext2': 368, 'IOAccelSharedUserClient2': 308,
    'IOAccelCommandQueue': 337, 'IOAccelDisplayPipe': 306, 'IOAccelMemoryMap': 57, 'IOFramebuffer': 350,
}
ACCEPT_PURE = {
    'IOFramebuffer': [309, 312, 313, 314, 315, 316, 317, 318],      # leaves.py FB_PURE
    'IOAccelDisplayPipe': [],                                        # 0 pure virtuals
}

# classes whose C++ declaration is public: the header's spelling is used for their slots (kind "sdk").
SDK_HEADERS = {'IOFramebuffer': 'IOKit/graphics/IOFramebuffer.h'}

# A class the SDK declares is normally NOT a class of this model (the generated header would both include the SDK
# header and declare the class itself - a duplicate definition).  IOAccelerator is the one exception, on request:
# the generated header declares it instead of including IOKit/graphics/IOAccelerator.h (which declares no virtual
# at all), so IOGraphicsAccelerator2 has a base class to name.  It is the last class of the model.
MODEL_EVEN_IF_IN_SDK = ('IOAccelerator',)

# sizeof(C) from the RE reference tree (a CROSS-CHECK: every number below is also measured from the binary) and,
# for IOFramebuffer, from the project's own document (gates/leaves.py: "IOFramebuffer (IOGraphicsFamily, 350
# slots, size 0x1d0, 8 pure ...)").  Used to label the provenance and to fall back when otool cannot answer.
REFERENCE_SIZES = {
    'IOAccelMemory': (0xb0, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelMemory.h kIOAccelMemorySize'),
    'IOAccelContext2': (0x10a8, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelContext2.h kIOAccelContext2Size'),
    'IOAccelSubmitter2': (0x568, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelSubmitter2.h kIOAccelSubmitter2Size'),
    'IOAccel2DContext2': (0x1100, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccel2DContext2.h kIOAccel2DContext2Size'),
    'IOAccelEventMachine2': (0xf0, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelEventMachine2.h kIOAccelEventMachine2Size'),
    'IOAccelEventMachineFast2': (0xd30, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelEventMachineFast2.h kIOAccelEventMachineFast2Size'),
    'IOAccelTask': (0x258, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelTask.h kIOAccelTaskSize'),
    'IOAccelDisplayMachine': (0x178, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelDisplayMachine.h kIOAccelDisplayMachineSize'),
    'IOAccelSysMemory': (0x198, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelSysMemory.h kIOAccelSysMemorySize'),
    'IOAccelMemoryMap': (0x118, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelMemoryMap.h kIOAccelMemoryMapSize'),
    'IOAccelVidMemory': (0x110, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelVidMemory.h kIOAccelVidMemorySize'),
    'IOAccelResource2': (0x180, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelResource2.h kIOAccelResource2Size'),
    'IOAccelDisplayPipe': (0x318, 'refs/nvidia-macos-driver/kexts/NVRM/accel/iofam/IOAccelDisplayPipe.h kIOAccelDisplayPipeSize'),
    'IOAccelSharedUserClient2': (0x168, 'refs/nvidia-macos-driver/kexts/NVRM/accel/re/IOAccelSharedUserClient2.h kIOAccelSharedUserClient2Size'),
    'IOGraphicsAccelerator2': (0xdd8, 'refs/nvidia-macos-driver/kexts/NVRM/accel/re/IOGraphicsAccelerator2.h kIOGraphicsAccelerator2Size'),
    'IOFramebuffer': (0x1d0, 'navi48accel/gates/leaves.py (0.0.4 M5: "IOFramebuffer (IOGraphicsFamily, 350 slots, size 0x1d0, 8 pure)")'),
    'IOAccelerator': (0x88, 'refs/nvidia-macos-driver/kexts/NVRM/accel/re/IOAccelerator.h kIOAcceleratorSize = 136 '
                             '(read from the kernel OSMetaClass registry)'),
}
# a second, independent witness for one class whose allocator is named in the family: the immediate of the
# `operator new` the factory performs (IOAccelCommandQueue has no RE reference at all).
ALLOC_SITE = {'IOAccelCommandQueue': ('IOGraphicsAccelerator2::newCommandQueue', '__ZN22IOGraphicsAccelerator215newCommandQueueEv')}


def sdk_roots():
    """the header roots the Navi48Accel build includes, MacKernelSDK first (-I is searched before -isysroot)."""
    repo = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))      # <repo>/tools/native/ioaccel-layout
    roots = [os.path.join(repo, 'src', 'RDNA4FB', 'MacKernelSDK', 'Headers')]
    try:
        sdk = subprocess.run(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], capture_output=True,
                             text=True).stdout.strip()
        if sdk:
            roots.append(os.path.join(sdk, 'System/Library/Frameworks/Kernel.framework/Versions/A/Headers'))
    except OSError:
        pass
    k = kcmod.kdk_root()
    if k:
        roots.append(os.path.join(k, 'System/Library/Frameworks/Kernel.framework/Versions/A/Headers'))
    return roots


_SDK_CLASSES = None


def sdk_classes():
    """every class/struct name the MacKernelSDK headers declare - the model's stop condition.

    A class the SDK declares must NOT be declared by the generated header as well (that would be a duplicate
    definition), so it never enters the model: the chain terminates at it.
    """
    global _SDK_CLASSES
    if _SDK_CLASSES is None:
        names = set()
        root = sdk_roots()[0]
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith(('.h', '.hpp')):
                    continue
                try:
                    text = strip_comments(open(os.path.join(dirpath, fn), errors='replace').read())
                except OSError:
                    continue
                names.update(re.findall(r'\b(?:class|struct)\s+([A-Za-z_]\w*)', text))
        _SDK_CLASSES = names
    return _SDK_CLASSES


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def pp_strip(text):
    """drop preprocessor lines (#pragma clang diagnostic push sits between IOFramebuffer's declarations)."""
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


_ACCESS = re.compile(r'^(?:public|protected|private)\s*:\s*')


def _clean_return(ret):
    """'public: virtual IOReturn' -> 'IOReturn'; reject anything that is not a type."""
    prev = None
    while ret != prev:
        prev = ret
        ret = _ACCESS.sub('', ret)
        ret = re.sub(r'^virtual\s+', '', ret).strip()
    if not ret or any(ch in ret for ch in '();{}='):
        return None
    return ret


def class_body(text, cls):
    """the body of `class <cls>` in an already comment-stripped header ('' when the header has no definition)."""
    text = pp_strip(text)
    m = re.search(r'\bclass\s+' + re.escape(cls) + r'\s*(?::|\{)', text)
    if not m:
        return ''
    end = text.find('\n};', m.end())
    return text[m.end():end if end > 0 else len(text)]


def header_declaration(cls, method, nargs, cache={}):
    """(ret, name, args, cv) of `method` as the SDK header declares it, matched by name AND parameter count."""
    key = (cls, method, nargs)
    if key in cache:
        return cache[key]
    cache[key] = None
    rel = SDK_HEADERS.get(cls)
    if not rel:
        return None
    for root in sdk_roots():
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        try:
            body = class_body(strip_comments(open(path, errors='replace').read()), cls)
        except OSError:
            continue
        if not body:
            continue
        pat = re.compile(r'(?:virtual\s+)?([A-Za-z_][\w:<>,\*&\s]*?)\s+' + re.escape(method) +
                         r'\s*\(([^;{()]*)\)\s*(const)?\s*(?:=\s*0)?\s*;')
        for m in pat.finditer(body):
            args = [re.sub(r'\s+', ' ', a).strip() for a in split_top(m.group(2)) if a and a != 'void']
            if len(args) != nargs:
                continue
            ret = _clean_return(re.sub(r'\s+', ' ', m.group(1)).strip())
            if not ret:
                continue
            out = (ret, method, args, ' const' if m.group(3) else '')
            cache[key] = out
            return out
    return None


# -------------------------------------------------------------------------------------------------------------------------------
# demangled-name helpers
# -------------------------------------------------------------------------------------------------------------------------------
def split_top(text):
    """split on commas at the top level (a template's <> or a paren list is not split)."""
    out, depth, cur = [], 0, ''
    for ch in text:
        if ch in '<([':
            depth += 1
        elif ch in '>)]':
            depth -= 1
        if ch == ',' and depth <= 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    out.append(cur)
    return [s.strip() for s in out]


_THUNK = re.compile(r'^(?:non-virtual |virtual )?thunk to ')


def parse_signature(demangled):
    """(class, name, args, cv) of a demangled C++ method, or None.

    'IOAccelEventMachine2::collectAllLiveEventIfNeeded() const'
        -> ('IOAccelEventMachine2', 'collectAllLiveEventIfNeeded', [], ' const')
    """
    d = _THUNK.sub('', (demangled or '').strip())
    m = re.match(r'^(.*?)::(~?[A-Za-z_]\w*)\s*\((.*)\)\s*(const)?\s*$', d, re.S)
    if not m:
        return None
    owner = m.group(1)
    owner = re.split(r'[<(]', owner)[0].split('::')[0].strip()
    if not owner or not (owner[0].isalpha() or owner[0] == '_'):
        return None
    return owner, m.group(2), split_top(m.group(3)), (' const' if m.group(4) else '')


# -------------------------------------------------------------------------------------------------------------------------------
# sizeof(C), measured from C's own OSMetaClass constructor
# -------------------------------------------------------------------------------------------------------------------------------
_SIZE_CACHE = {}


def function_disasm(binary_path, symbol, limit=60):
    """[(address, instruction)] of <symbol> in a Mach-O, from `otool -tV -p`, cut at the function's ret."""
    out = subprocess.run(['otool', '-arch', 'x86_64', '-t', '-v', '-p', symbol, binary_path],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        if not line.startswith('0000'):
            continue
        parts = [p.strip() for p in line.split('\t') if p.strip()]
        if len(parts) < 2:
            continue
        insn = ' '.join(parts[1:]).split('##')[0].strip()      # otool appends "## imm = 0x..." comments
        rows.append((parts[0], insn))
        if re.search(r'\bret(q|l|w)?\b', insn) or len(rows) >= limit:
            break
    return rows


def _size_from_immediate(rows, reg):
    """the first `movl $imm, %<reg>` that is immediately followed by a call -> (value, address, next insn)."""
    for i, (addr, insn) in enumerate(rows):
        m = re.match(r'movl\s+\$(0x[0-9a-fA-F]+|\d+),\s*%' + reg + r'$', insn)
        if m and i + 1 < len(rows) and rows[i + 1][1].startswith('call'):
            return int(m.group(1), 16), addr, rows[i + 1][1]
    return None, None, None


def measure_size(cls, binary_path, tag):
    """(size, source, confidence) for sizeof(<cls>): the classSize argument of OSMetaClass's constructor.

    OSDefineMetaClassAndStructors(C, P) emits `C::MetaClass::MetaClass() : OSMetaClass(#C, C::superClass,
    sizeof(C))`, so both the complete-object (C1) and base-object (C2) constructor carry the size as the 4th
    argument - `movl $<sizeof(C)>, %ecx` right before the OSMetaClass constructor call.  The value is exactly
    what OSMetaClass::getClassSize() returns, i.e. what the runtime layout gate compares against.
    """
    key = (cls, tag)
    if key in _SIZE_CACHE:
        return _SIZE_CACHE[key]
    sizes, evidence = [], []
    for suffix, flavour in (('C1Ev', 'C1'), ('C2Ev', 'C2')):
        sym = '__ZN%d%s9MetaClass%s' % (len(cls), cls, suffix)
        size, addr, nxt = _size_from_immediate(function_disasm(binary_path, sym), 'ecx')
        if size:
            sizes.append(size)
            evidence.append('%s @%s' % (sym, addr))
    extra = []
    if cls in ALLOC_SITE:
        label, sym = ALLOC_SITE[cls]
        size, addr, _nxt = _size_from_immediate(function_disasm(binary_path, sym), 'edi')
        if size:
            sizes.append(size)
            extra.append('%s @%s movl $%#x,%%edi (operator new) agrees' % (label, addr, size))
    name = os.path.basename(binary_path)[:-len('.x86_64')] if binary_path.endswith('.x86_64') \
        else os.path.basename(binary_path)
    if sizes:
        size = sizes[0]
        src = 'measured: %s movl $%#x,%%ecx (%s, x86_64)' % (', '.join(evidence), size, name)
        if len(set(sizes)) > 1:
            src += '; WARNING: witnesses disagree: %s' % [hex(s) for s in sizes]
        if extra:
            src += '; ' + '; '.join(extra)
        conf = 'measured'
    elif cls in REFERENCE_SIZES:
        size, ref = REFERENCE_SIZES[cls]
        src = 'reference (otool could not decode): %s' % ref
        conf = 'reference'
    else:
        size, src, conf = 0, 'unknown: no OSMetaClass constructor found in %s and no reference' % name, 'unknown'
    if conf == 'measured' and cls in REFERENCE_SIZES:
        ref_size, ref = REFERENCE_SIZES[cls]
        if ref_size == size:
            src += '; reference agrees: %s [%#x]' % (ref, ref_size)
        else:
            src += '; reference DISAGREES: %s [%#x]' % (ref, ref_size)
    _SIZE_CACHE[key] = (size, src, conf)
    return _SIZE_CACHE[key]


# -------------------------------------------------------------------------------------------------------------------------------
class Model(object):
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.images = {'FAMILY': kcmod.load(kcmod.FAMILY), 'IOGF': kcmod.load(kcmod.IOGF)}
        self.export_names = exports.load()
        # (lvl, va) by name - the resolution order of gates/layout_gate_host.py::sym_addr_table()
        self.table = {}
        for lvl, path in ((1, kcmod.FAMILY), (0, kcmod.BOOT_KC), (1, kcmod.SYS_KC)):
            for name, va in kcmod.nm_table(path).items():
                self.table.setdefault(name, (lvl, va))
        # one global class -> base map (FAMILY/IOGF first: they are the authority for their own classes)
        self.sup = {}
        self.classes = {}                      # plain class name -> [ (kind, value) ] (trailing zeros kept)
        self.vt_tag = {}                       # plain class name -> the image tag its vtable lives in
        for tag in ('FAMILY', 'IOGF'):
            img = self.images[tag]
            for cls, base in img.super_map().items():
                self.sup.setdefault(cls, base)
            for key, rows in img.vtables().items():
                m = re.match(r'^(\d+)(.*)$', key)
                name = m.group(2) if m else key
                self.classes.setdefault(name, rows)
                self.vt_tag.setdefault(name, tag)
        self.providers = []                    # lazily loaded: [(name, MachO|None)]
        self._provider_paths = None
        self._closure = None
        self.dm_cache = {}
        self.sig_cache = {}
        self.imp_cache = {}

    # -- c++filt, batched ------------------------------------------------------
    def prewarm(self, names):
        """demangle (in ONE c++filt call) every name not in the cache yet."""
        todo = sorted(set(n for n in names if n and n.startswith('__') and n not in self.dm_cache))
        if not todo:
            return
        for n, d in zip(todo, kcmod.demangle(todo)):
            self.dm_cache[n] = d

    def demangled(self, name):
        if name not in self.dm_cache:
            self.prewarm([name])
        return self.dm_cache.get(name, name or '')

    # -- closure ---------------------------------------------------------------
    def closure(self):
        """[(class, image tag)]: the 14 roots plus every ancestor the SDK headers do not declare.

        Iterating the growing list walks the chain breadth-first in a stable order, so the 14 roots keep their
        positions (and their entries in the generated JSON files stay byte-identical).
        """
        if self._closure is not None:
            return self._closure
        sdk = sdk_classes()
        normal, forced, seen = list(PARENTS), [], set(c for c, _ in PARENTS)
        queue = list(PARENTS)
        while queue:
            cls, _tag = queue.pop(0)
            sup = self.sup.get(cls)
            if not sup or sup in seen:
                continue
            exempt = sup in MODEL_EVEN_IF_IN_SDK
            if sup in sdk and not exempt:
                continue                      # SDK-declared: the generated header must not declare it
            tag = self.vt_tag.get(sup)
            if tag is None:
                self.note('ancestor %s of %s has no vtable here: not modelled' % (sup, cls))
                continue
            seen.add(sup)
            queue.append((sup, tag))
            (forced if exempt else normal).append((sup, tag))
        self._closure = normal + forced       # the SDK-exempt ones last: the previous revision's bytes stay a prefix
        return self._closure

    # -- providers -------------------------------------------------------------
    def provider_paths(self):
        """the other kexts of the same KDK that carry concrete subclasses of the family's abstract classes.

        AppleParavirtGPU answers every pure slot this model needs; the AMD driver kexts are fallbacks only, and
        no provider is opened until a pure slot asks for one (IOACCEL_LAYOUT_PROVIDERS overrides the list).
        """
        if self._provider_paths is None:
            k = kcmod.kdk_root()
            names = os.environ.get('IOACCEL_LAYOUT_PROVIDERS')
            names = names.split(',') if names else ['AppleParavirtGPU', 'AppleParavirtGPUIOGPUFamily',
                                                    'AMDRadeonX6000', 'AMDRadeonX6000HWServices',
                                                    'AMDRadeonX6000Framebuffer']
            self._provider_paths = []
            for n in names:
                path = os.path.join(k or '', 'System/Library/Extensions', n + '.kext', 'Contents', 'MacOS', n)
                if os.path.exists(path):
                    self._provider_paths.append((n, path))
        return self._provider_paths

    def provider(self, i):
        """the i-th provider kext, loaded once (its classes and superClass entries join the global maps)."""
        while len(self.providers) <= i:
            n, path = self.provider_paths()[len(self.providers)]
            try:
                img = kcmod.load(path)
                vt = img.vtables()
            except (ValueError, OSError) as e:
                self.note('provider %s unreadable: %s' % (n, e))
                self.providers.append((n, None))
                continue
            self.providers.append((n, img))
            for cls, base in img.super_map().items():
                self.sup.setdefault(cls, base)          # only fills what FAMILY/IOGF did not define
            for key, rows in vt.items():
                m = re.match(r'^(\d+)(.*)$', key)
                name = m.group(2) if m else key
                self.classes.setdefault(name, rows)
        return self.providers[i]

    def ancestors(self, cls, limit=32):
        """the chain of base class names above <cls> (self.sup is global, so it crosses binaries)."""
        out, seen, cur = [], {cls}, cls
        for _ in range(limit):
            cur = self.sup.get(cur)
            if not cur or cur in seen:
                break
            seen.add(cur)
            out.append(cur)
        return out

    # -- slots -----------------------------------------------------------------
    def read(self, cls, tag):
        """(rows, nterm) of __ZTV<cls>: every slot with its symbol names, trailing zero slots dropped."""
        img = self.images[tag]
        va, raw = img.rows(cls)
        if raw is None:
            raise SystemExit('model.py: %s has no __ZTV%s' % (tag, cls))
        rows = []
        for slot_va, kind, value in raw:
            row = dict(slot_va=slot_va, kind=kind, target=value, names=[], primary=None, pure=False)
            if kind == 'ext':
                row['names'] = [value]
                row['primary'] = value
            elif kind == 'addr':
                names = list(img.names_at.get(value) or [])
                row['names'] = names or ['0x%x' % value]
                row['primary'] = names[0] if names else '0x%x' % value
            row['pure'] = bool(row['primary']) and 'cxa_pure_virtual' in row['primary']
            rows.append(row)
        nterm = 0
        while rows and rows[-1]['kind'] == 'zero' and not rows[-1]['primary']:
            rows.pop()
            nterm += 1
        self.prewarm([r['primary'] for r in rows])
        return rows, nterm

    def resolve(self, name):
        return self.table.get(name)

    def own(self, cls, row):
        """the slot's symbol belongs to <cls>: an introduced or an overridden method."""
        if not row['primary'] or not row['primary'].startswith('__'):
            return False
        parsed = parse_signature(self.demangled(row['primary']))
        return bool(parsed) and parsed[0] == cls

    def implementer(self, cls, index):
        """the symbol a concrete subclass of <cls> has at slot <index> (the recovery of a pure slot's signature).

        A pure slot of <cls> has no symbol of its own, but every concrete subclass implements it.  A subclass in
        the same image wins (IOAccelEventMachineFast2 implements IOAccelEventMachine2's pure slots), then the
        providers in order (AppleParavirt* before the AMD driver).  The candidate's own symbol - or one of a
        class between it and <cls> - names the signature.
        """
        if (cls, index) in self.imp_cache:
            return self.imp_cache[(cls, index)]
        result = None
        for rank in range(1 + len(self.provider_paths())):
            if rank == 0:
                group = list(self.images.items())
            else:
                group = [self.provider(rank - 1)]
                if group[0][1] is None:
                    continue
            raw = []
            for tag, img in group:
                for key, rows in img.vtables().items():
                    m = re.match(r'^(\d+)(.*)$', key)
                    cand = m.group(2) if m else None
                    if not cand or cand == cls or len(rows) <= index:
                        continue
                    kind, value = rows[index]
                    if kind not in ('addr', 'ext') or not value:
                        continue
                    name = value if kind == 'ext' else img.byaddr.get(value)
                    if not name or 'cxa_pure' in name or not name.startswith('__'):
                        continue
                    chain = self.ancestors(cand)
                    if cls in chain:
                        raw.append((chain.index(cls), cand, name, chain))
            if not raw:
                continue
            dms = dict(zip([n for _, _, n, _ in raw], kcmod.demangle([n for _, _, n, _ in raw])))
            ok = []
            for dist, cand, name, chain in raw:
                parsed = parse_signature(dms[name])
                if not parsed or (parsed[0] != cand and parsed[0] not in chain):
                    continue
                ok.append((dist, cand, name))
            if ok:
                ok.sort()
                result = ok[0][2]
                break
        self.imp_cache[(cls, index)] = result
        return result

    def sig_for(self, cls, index, row):
        """(kind, name, args, cv) for one slot: 'sdk' (SDK header), 'real' (a symbol) or 'placeholder'."""
        if (cls, index) in self.sig_cache:
            return self.sig_cache[(cls, index)]
        out = ('placeholder', row.get('primary') or '', '', '')
        symbol = row.get('primary') if (row.get('primary') or '').startswith('__') else None
        parsed = parse_signature(self.demangled(symbol)) if symbol else None
        if parsed is None and row.get('pure'):
            provider = self.implementer(cls, index)
            if provider:
                symbol = provider
                parsed = parse_signature(self.demangled(provider))
        if parsed:
            decl = header_declaration(cls, parsed[1], len(parsed[2]))
            if decl:
                ret, name, args, cv = decl
                out = ('sdk', '%s %s(%s)' % (ret, name, ', '.join(args)), ', '.join(args), cv)
            else:
                out = ('real', parsed[1], ', '.join(parsed[2]), parsed[3])
        self.sig_cache[(cls, index)] = out
        return out

    def reachable(self, scope, cls, index):
        """would gen_tramp.py's visible(SJ, cls, index) find an entry (walking the super chain)?"""
        cur = cls
        for _ in range(32):
            d = scope.get(cur)
            if d and str(index) in d['entries']:
                return True
            cur = self.sup.get(cur)
            if not cur:
                break
        return False

    # -- build -----------------------------------------------------------------
    def build(self):
        model, forwarded, per = {'classes': {}}, {}, {}
        for cls, tag in self.closure():
            rows, nterm = self.read(cls, tag)
            mrows, fwd, entries = [], [], {}
            for i, row in enumerate(rows):
                if row['kind'] == 'zero' and not row['primary']:
                    lvl, ava = 1, row['slot_va']              # a hole: no name, keep the field non-zero
                else:
                    hit = self.resolve(row['primary'])
                    if hit:
                        lvl, ava = hit
                    else:
                        # not exported by family/kernel: the leaf reaches it through the parent's vtable only
                        lvl, ava = 1, (row['target'] if row['kind'] == 'addr' else row['slot_va'])
                        fwd.append(i)
                mrows.append({'i': i, 'pure': row['pure'], 'mangled': row['names'], 'lvl': lvl, 'va': ava})
                if self.own(cls, row) or row['pure']:
                    kind, name, args, cv = self.sig_for(cls, i, row)
                    entries[str(i)] = {'kind': kind, 'name': name, 'args': args, 'cv': cv, 'owner': cls}
            per[cls] = dict(raw=rows, fwd=fwd, entries=entries)
            model['classes'][cls] = {'nslots': len(rows), 'nterm': nterm, 'rows': mrows}
            if fwd:
                forwarded[cls] = fwd
        # A forwarded slot is the parent's own responsibility: gen_tramp.py emits one forwarder per forwarded slot
        # and its declaration must be reachable from the parent.  When the symbol belongs to another class the
        # chain resolves it (N48_R_<that class>_<slot>: slots 70/72/73 of the event machine come from
        # IOAccelEventMachine2, exactly as Navi48Accel.cpp pins them); otherwise the parent lists the slot itself.
        #
        # The 14 ROOTS are resolved against the 14 only, so their entries stay byte-identical to the pre-closure
        # model (a forwarded slot inherited from a closure class keeps its entry on the root; the closure class
        # now carries the same slot under its true owner as well).  Set IOACCEL_LAYOUT_FREEZE_ROOTS=0 to let the
        # roots resolve through the whole closure instead - that drops those entries.
        roots = {cls: per[cls] for cls, _tag in PARENTS if cls in per}
        freeze = os.environ.get('IOACCEL_LAYOUT_FREEZE_ROOTS', '1') != '0'
        for cls, _tag in self.closure():
            d = per[cls]
            scope = roots if (freeze and cls in roots) else per
            for i in d['fwd']:
                if self.reachable(scope, cls, i):
                    continue
                kind, name, args, cv = self.sig_for(cls, i, d['raw'][i])
                d['entries'][str(i)] = {'kind': kind, 'name': name, 'args': args, 'cv': cv, 'owner': cls}
        slots = {'classes': {}}
        for cls, _tag in self.closure():
            slots['classes'][cls] = {'super': self.sup.get(cls), 'slots': per[cls]['entries']}
        return model, forwarded, slots

    def sizes(self, model):
        """{class: {size, source, confidence}} for every class of the model (plus IOAccelerator)."""
        out = {}
        for cls, tag in self.closure():
            size, source, conf = measure_size(cls, self.images[tag].thin_path, tag)
            out[cls] = {'size': size, 'source': source, 'confidence': conf}
        return out

    def note(self, msg):
        if not self.quiet:
            print('model.py: ' + msg, file=sys.stderr)


# -------------------------------------------------------------------------------------------------------------------------------
def write_json(path, obj):
    if not os.path.isdir(GEN_DIR):
        os.makedirs(GEN_DIR)
    with open(path, 'w') as f:
        json.dump(obj, f, indent=1, sort_keys=False)
        f.write('\n')
    return path


TSV_COLUMNS = ['idx', 'va', 'mangled', 'kind', 'level', 'address', 'demangled']


def sha256_file(path):
    import hashlib
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_tsv(path, img, cls, vrows, model_rows, entries, size, demangled):
    """vtables/<cls>.tsv - the vtable listing the framebuffer tests read.

    Column contract (navi48accel/tests/host_test.cpp): 0 = slot index, 3 = "PURE" for a slot whose target is
    __cxa_pure_virtual (no other row may say PURE), 6 = demangled name (__cxa_pure_virtual for a pure slot).
    Column 3 is "PURE", else the slots.json kind of that row ("real"/"sdk"/"placeholder") when the class
    declares the slot itself, else "inherited" (the slot comes from the base class named in column 6).
    Level/address are the model's (lvl, va): level 1 = IOAcceleratorFamily2 (System KC), level 0 = kernel.
    Lines starting with '#' are ignored by the readers.
    """
    if not os.path.isdir(VT_DIR):
        os.makedirs(VT_DIR)
    lines = ['# %s vtable - GENERATED by tools/native/ioaccel-layout/model.py, do not edit' % cls,
             '# source: %s (x86_64) sha256 %s  sizeof(%s) = %#x' %
             (img.thin_path, sha256_file(img.thin_path)[:16], cls, size),
             '# columns: ' + '  '.join(TSV_COLUMNS)]
    for vrow, r in zip(vrows, model_rows):
        mangled = r['mangled'][0] if r['mangled'] else '-'
        if r['pure']:
            kind, dem = 'PURE', '__cxa_pure_virtual'
        else:
            e = entries.get(str(r['i']))
            kind = e['kind'] if e else 'inherited'
            dem = demangled.get(mangled, mangled)
        lines.append('%d\t%#x\t%s\t%s\t%d\t%#x\t%s' % (r['i'], vrow['slot_va'], mangled, kind, r['lvl'], r['va'], dem))
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return path


def check(model, forwarded, slots, closure):
    """the acceptance line: slot counts, IOFramebuffer's 8 pure slots, IOAccelDisplayPipe's 0, nterm >= 1."""
    bad = []
    for cls, want in sorted(ACCEPT_SLOTS.items()):
        have = model['classes'].get(cls, {}).get('nslots')
        if have != want:
            bad.append('%s: %s slots, the table says %d' % (cls, have, want))
    for cls, want in sorted(ACCEPT_PURE.items()):
        have = [r['i'] for r in model['classes'][cls]['rows'] if r['pure']]
        if have != want:
            bad.append('%s: pure slots %s, expected %s' % (cls, have, want))
    for cls, c in sorted(model['classes'].items()):
        if c['nterm'] < 1:
            bad.append('%s: nterm %d (must be >= 1)' % (cls, c['nterm']))
        for r in c['rows']:
            if ((r['lvl'] << 60) ^ (r['va'] & 0x0fffffffffffffff)) == 0:
                bad.append('%s slot %d: (lvl, va) encodes 0' % (cls, r['i']))
    for cls, f in sorted(forwarded.items()):
        if not f:
            bad.append('%s: empty forwarded entry' % cls)
    for cls, c in sorted(slots['classes'].items()):
        if c['super'] == cls:
            bad.append('%s: super points at itself' % cls)
    sdk = sdk_classes()
    for cls, c in sorted(slots['classes'].items()):
        sup = c['super']
        if sup and sup not in slots['classes'] and sup not in sdk:
            bad.append('%s: super %s is neither a model class nor SDK-declared' % (cls, sup))
    return bad


def main(argv):
    check_only = '--check' in argv
    quiet = '--quiet' in argv or check_only
    missing = [p for p, ok in kcmod.check_inputs().items() if not ok]
    if missing:
        raise SystemExit('model.py: missing input binary: ' + ', '.join(missing))
    m = Model(quiet=quiet)
    model, forwarded, slots = m.build()
    sizes = m.sizes(model)
    write_json(MODEL_JSON, model)
    write_json(FORWARDED_JSON, forwarded)
    write_json(SLOTS_JSON, slots)
    write_json(SIZES_JSON, sizes)
    cls, tag = 'IOFramebuffer', 'IOGF'
    img = m.images[tag]
    vrows, _nterm = m.read(cls, tag)
    mrows = model['classes'][cls]['rows']
    names = [r['mangled'][0] for r in mrows if r['mangled']]
    dem = dict(zip(names, kcmod.demangle(names)))
    tsv = write_tsv(os.path.join(VT_DIR, cls + '.tsv'), img, cls, vrows, mrows,
                    slots['classes'][cls]['slots'], sizes[cls]['size'], dem)
    closure = m.closure()
    bad = check(model, forwarded, slots, closure)
    if check_only:
        if bad:
            print('ACCEPTANCE FAIL')
            for b in bad:
                print('  ' + b)
            return 1
        print('model.py: OK (%d classes, %d slots)' %
              (len(model['classes']), sum(c['nslots'] for c in model['classes'].values())))
        return 0
    if quiet:
        print('wrote %s, %s, %s, %s, %s' % (MODEL_JSON, FORWARDED_JSON, SLOTS_JSON, SIZES_JSON, tsv))
        return 1 if bad else 0
    print('inputs:')
    for label, path in (('FAMILY', kcmod.FAMILY), ('IOGF', kcmod.IOGF),
                        ('BOOT_KC', kcmod.BOOT_KC), ('SYS_KC', kcmod.SYS_KC)):
        print('  %-8s %s' % (label, path))
    print('  IOGF x86_64 slice: %s' % m.images['IOGF'].thin_path)
    print('%d exported symbol names (exports.py), %d (name -> lvl, va) resolutions' %
          (len(m.export_names), len(m.table)))
    print()
    print('%-26s %-8s %6s %5s %6s %6s  %-24s %s' %
          ('class', 'kind', 'nslots', 'nterm', 'pure', 'non-exp', 'super', 'pure slot list'))
    roots = set(c for c, _ in PARENTS)
    for cls, _tag in closure:
        c = model['classes'][cls]
        pure = [r['i'] for r in c['rows'] if r['pure']]
        print('%-26s %-8s %6d %5d %6d %6d  %-24s %s' % (cls, 'root' if cls in roots else 'closure',
                                                        c['nslots'], c['nterm'], len(pure),
                                                        len(forwarded.get(cls, [])),
                                                        slots['classes'][cls]['super'] or '?', pure))
    print()
    kinds, place = {}, []
    for cls, c in slots['classes'].items():
        for i, e in c['slots'].items():
            kinds[e['kind']] = kinds.get(e['kind'], 0) + 1
            if e['kind'] == 'placeholder':
                place.append('%s[%s]' % (cls, i))
    print('slot declarations: %s%s' % (', '.join('%s=%d' % kv for kv in sorted(kinds.items())),
                                       ('; placeholders: ' + ', '.join(place[:12])) if place else ''))
    print('sizes: ' + ', '.join('%s %#x (%s)' % (c, sizes[c]['size'], sizes[c]['confidence'])
                                for c, _t in closure))
    print('wrote %s, %s, %s, %s, %s' % (MODEL_JSON, FORWARDED_JSON, SLOTS_JSON, SIZES_JSON, tsv))
    if bad:
        print()
        for b in bad:
            print('ACCEPTANCE FAIL: ' + b)
        return 1
    print('acceptance: %d root classes with the expected slot counts (%d roots + %d closure), every nterm >= 1, '
          'no zero (lvl, va), IOFramebuffer pure %s, IOAccelDisplayPipe pure []' %
          (len(ACCEPT_SLOTS), len(PARENTS), len(closure) - len(PARENTS),
           [r['i'] for r in model['classes']['IOFramebuffer']['rows'] if r['pure']]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
