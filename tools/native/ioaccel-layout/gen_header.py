#!/usr/bin/env python3
"""gen_header.py — 从 ioaccel-layout/generated/*.json 生成 IOAccelFamily2_decl.h（Navi48Accel.cpp:72 引入）。

与消费方（Navi48Accel.cpp / gates/*.py）的契约：

1. 只能为每个类声明"**该类自己定义的槽**"，外加本类 vtable 上的纯虚槽。槽目标的 mangled 名带定义类名，
   在子类里重声明继承来的方法会产生错误符号（C::m 而非 Base::m），gate A 直接判失败。
   "谁定义了这个槽"以 **model.json 里该槽 mangled 别名的定义类**为准（slots.json 的 owner 字段不是权威）。
2. 槽 0/1（两个析构）与槽 7（getMetaClass）**不声明**：`OSDeclareDefaultStructors(C)` 已提供
   （`virtual ~C()` → C::~C()；`virtual const OSMetaClass * getMetaClass() const` → C::getMetaClass）。
3. 返回类型优先级（决定 trampoline 声明能否与基类一致）：
   (1) Navi48Accel.cpp 钉死的 N48_R_* 宏（作者真机验证过的真值）；
   (2) 与 SDK 声明做**类型级**匹配（名字 + 归一化参数类型元组）→ 整条用 SDK 签名（合法覆写）；
   (3) 同名同参数个数但拼写不同（枚举/typedef）→ 只借 SDK 的返回类型，参数保留模型的 ABI 拼写；
   (4) 兜底 void。
   归一化要点：mangled 名编码的是 ABI 类型（typedef 透明），所以要把 SDK 侧经 typedef 归一到 ABI 拼写，
   并剥掉默认实参与注解宏；且只有 SDK 侧才能丢"参数名"（模型侧是纯类型）。
4. 槽 0/1/7 之外的**每个槽条目**都要有 N48_R_<owner>_<slot> 的 `#ifndef` 兜底宏，值 = 该槽最终声明的返回类型
   （不是 blanket void）——否则 trampoline 声明会与基类返回类型冲突。
5. 前向声明**所有**族类（含模型类）：它们可能只出现在 Navi48Accel.cpp 的 pinned 宏里，而宏在本头之前定义，
   会在本头内部展开；类定义若更靠后就会 unknown type name。
6. 为 forwarded.json 里的每个父类输出 `N48_FWD_DECLS_<P>` / `N48_FWD_DEFS_<P>(Leaf)`：非导出槽的
   naked tail-jump（与 gates/gen_tramp.py 对 TRAMP 叶子做的事一致，但那些叶子不在 TRAMP 里）。
7. 每个非 SDK 类补 `_opaque` 到真实实例尺寸（条件表达式，避免 base 更大时为负）。
8. 导出 split_args / san（gates/gen_tramp.py 依赖）。输出确定性（无时间戳、固定顺序），N48_GEN_OUT 指定目录。
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, 'generated')
OUTDIR = os.environ.get('N48_GEN_OUT', GEN)
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
MKSDK = os.path.join(REPO, 'src', 'RDNA4FB', 'MacKernelSDK', 'Headers')
MACRO_SLOTS = {0, 1, 7}
SDK_FALLBACK = {
    'OSObject': 'libkern/c++/OSObject.h', 'IOService': 'IOKit/IOService.h',
    'IORegistryEntry': 'IOKit/IORegistryEntry.h', 'IOUserClient': 'IOKit/IOUserClient.h',
    'IOFramebuffer': 'IOKit/graphics/IOFramebuffer.h',
    'IOGraphicsDevice': 'IOKit/graphics/IOGraphicsDevice.h',
    'IOAccelerator': 'IOKit/graphics/IOAccelerator.h',
    'OSMetaClass': 'libkern/c++/OSMetaClass.h',
}
ALWAYS_HEADERS = [
    'libkern/c++/OSObject.h', 'libkern/c++/OSMetaClass.h',
    'IOKit/IOTypes.h', 'IOKit/IOService.h', 'IOKit/IOUserClient.h',
    'IOKit/graphics/IOGraphicsTypes.h', 'IOKit/graphics/IOFramebuffer.h',
    'IOKit/IOReportTypes.h',
]
EXTRA_HEADERS = {
    'IOPCIDevice': 'IOKit/pci/IOPCIDevice.h', 'IOMemoryDescriptor': 'IOKit/IOMemoryDescriptor.h',
    'IORangeAllocator': 'IOKit/IORangeAllocator.h', 'IOCommandGate': 'IOKit/IOCommandGate.h',
    'IOWorkLoop': 'IOKit/IOWorkLoop.h', 'IOEventSource': 'IOKit/IOEventSource.h',
    'IODMACommand': 'IOKit/IODMACommand.h', 'IOMemoryMap': 'IOKit/IOMemoryMap.h',
    'IODeviceMemory': 'IOKit/IODeviceMemory.h', 'IOGraphicsTypes': 'IOKit/graphics/IOGraphicsTypes.h',
}
BUILTIN = set('''
void bool int unsigned signed char short long float double size_t uint8_t uint16_t uint32_t uint64_t
int8_t int16_t int32_t int64_t IOReturn kern_return_t IOOptionBits IOItemCount IOByteCount vm_address_t
addr64_t mach_vm_address_t mach_vm_size_t task_t thread_t IOIndex IOPhysicalAddress IOPhysicalLength
const struct enum class volatile union
'''.split())

_c, _c2, _c3 = {}, {}, {}

def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def _pick(hits, base=MKSDK):
    hits = [h for h in hits if h.strip()]
    if not hits:
        return None
    hits.sort(key=lambda p: (0 if '/IOKit/' in p else 1 if '/libkern/' in p else 2, len(p)))
    return os.path.relpath(hits[0], base)

def sdk_class_header(name):
    if name in _c:
        return _c[name]
    r = sh(['grep', '-rl', '^class %s[[:space:]:{]' % name, MKSDK])
    out = _pick(r.stdout.splitlines())
    if out is None and name in SDK_FALLBACK and os.path.exists(os.path.join(MKSDK, SDK_FALLBACK[name])):
        out = SDK_FALLBACK[name]
    _c[name] = out
    return out

def is_declared_type(name):
    """KDK 里是否已把它声明为 typedef / struct / union / enum：这类名字由 include 提供，不能前向声明为 class。"""
    if name in _c2:
        return _c2[name]
    pat = r'(\b(typedef|struct|union|enum)\b[^;]*\b%s\b)|(^ *\} *%s *;)' % (name, name)
    r = sh(['grep', '-rlE', pat, MKSDK])
    out = bool([l for l in r.stdout.splitlines() if l.strip()])
    _c2[name] = out
    return out

TYPEDEFS = None
def typedef_table():
    global TYPEDEFS
    if TYPEDEFS is not None:
        return TYPEDEFS
    tab = {'task_t': 'struct task *', 'thread_t': 'struct thread *',
           'vm_map_t': 'struct _vm_map *', 'vm_object_t': 'struct vm_object *',
           'ipc_port_t': 'struct ipc_port *', 'ipc_space_t': 'struct ipc_space *',
           'uint8_t': 'unsigned char', 'uint16_t': 'unsigned short',
           'uint32_t': 'unsigned int', 'uint64_t': 'unsigned long long',
           'int8_t': 'signed char', 'int16_t': 'short', 'int32_t': 'int', 'int64_t': 'long long',
           'UInt8': 'unsigned char', 'UInt16': 'unsigned short',
           'UInt32': 'unsigned int', 'UInt64': 'unsigned long long',
           'SInt8': 'signed char', 'SInt16': 'short', 'SInt32': 'int', 'SInt64': 'long long',
           'size_t': 'unsigned long', 'uintptr_t': 'unsigned long'}
    r = sh(['grep', '-rhE', r'^typedef[[:space:]]+.*[[:space:]][A-Za-z_][A-Za-z0-9_]*[[:space:]]*;$', MKSDK])
    for line in r.stdout.splitlines():
        m = re.match(r'^typedef\s+(.+?)\s+([A-Za-z_]\w*)\s*;$', line.strip())
        if m:
            tab.setdefault(m.group(2), m.group(1))
    TYPEDEFS = tab
    return tab

def canon_type(t, depth=0):
    t = re.sub(r'\b(struct|class|union|enum)\b', ' ', t).strip()
    qual = ''
    if t.startswith('const'):
        qual, t = 'const', t[5:].strip()
    stars = ''
    while t and t[-1] in '*&':
        stars = t[-1] + stars
        t = t[:-1].strip()
    base = ''.join(t.split())
    tab = typedef_table()
    if depth < 6 and base in tab:
        inner = canon_type(tab[base], depth + 1)
        return (qual + inner).replace(' ', '') + stars if qual else inner.replace(' ', '') + stars
    return (qual + base) + stars

def split_args(args):
    """顶层逗号切分参数列表，返回原始片段（gates/gen_tramp.py 依赖这个导出）。"""
    out, cur, depth = [], '', 0
    for ch in args:
        if ch in '(<[':
            depth += 1
        elif ch in ')>]':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    out.append(cur)
    return [a.strip() for a in out]

def norm_args(args, drop_names=False):
    res = []
    for p in split_args(args):
        p = p.split('=')[0].split('...')[0]
        p = re.sub(r'\b(LIBKERN|APPLE_KEXT|OS|API|__)[A-Z_]+\b', ' ', p)
        toks = p.split()
        if drop_names and len(toks) > 1 and re.fullmatch(r'[A-Za-z_]\w*', toks[-1]):
            toks = toks[:-1]
        if toks:
            res.append(canon_type(''.join(toks)))
    return tuple(t for t in res if t and t != 'void')

def strip_comments(s):
    s = re.sub(r'/\*.*?\*/', ' ', s, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', s)

def parse_sdk(rel):
    path = os.path.join(MKSDK, rel)
    if not os.path.exists(path):
        return None, {}
    txt = strip_comments(open(path, errors='replace').read())
    m = re.search(r'\bclass\s+(\w+)\s*:\s*public\s+(\w+)', txt)
    base = m.group(2) if m else None
    sigs = {}
    for m in re.finditer(r'\bvirtual\s+([^;{}=()]+?)\s+(\w+)\s*\(([^)]*)\)\s*(const)?\s*(?:APPLE_KEXT_OVERRIDE)?\s*(?:=\s*0)?\s*;', txt, flags=re.S):
        ret = ' '.join(m.group(1).split())
        name, args = m.group(2), ' '.join(m.group(3).split())
        if ret.endswith('~') or name == '~':
            continue
        sigs.setdefault((name, norm_args(args, drop_names=True)), (ret, args, ' const' if m.group(4) else ''))
    return base, sigs

def argc(args):
    return len([a for a in split_args(args) if a and a != 'void'])

def ret_of_sig(sig):
    """从 'IOReturn foo(int x) const' 取返回类型"""
    m = re.match(r'^(.*?)\s+(\w+)\s*\(', sig)
    return m.group(1).strip() if m else 'void'

def san(s):
    return re.sub(r'[^A-Za-z0-9_]', '_', s or '')

def load(name, required=True):
    p = os.path.join(GEN, name)
    if not os.path.exists(p):
        if required:
            raise SystemExit('缺少 %s（先跑 model.py）' % p)
        return {}
    return json.load(open(p))

def defining_class(mangled):
    m = re.match(r'^__ZNK?(\d+)([A-Za-z0-9_]+)', mangled or '')
    if not m:
        return None
    n, rest = int(m.group(1)), m.group(2)
    return rest[:n] if len(rest) >= n else None

def owned_by(row, c):
    if not row:
        return False
    if row.get('pure'):
        return True
    return any(defining_class(a) == c for a in (row.get('mangled') or []))

def pinned_macros(path):
    """Navi48Accel.cpp 里 `#define N48_R_<C>_<i> <type>` → {(C,i): type}"""
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, errors='replace'):
        m = re.match(r'\s*#define\s+(N48_R_(\w+)_(\d+))\s+(.+?)\s*(?://.*)?$', line)
        if m:
            out[(m.group(2), int(m.group(3)))] = (m.group(1), m.group(4).strip())
    return out

def consumer_placeholders(path):
    """消费方（Navi48Accel.cpp）里手写的 `_vslot<N>() override`：这些槽必须由本头声明为占位符
    `virtual void _vslotN();`，否则那边的 override 编译不过（`override` 要求基类确有该虚函数）。
    作者当年的模型解不出这些槽的名字，于是形成了这个约定；模型的槽号与之一致。"""
    out = {}
    if not os.path.exists(path):
        return out
    txt = strip_comments(open(path, errors='replace').read())
    cur, depth = None, 0
    for line in txt.splitlines():
        m = re.match(r'\s*class\s+(\w+)\s*:\s*public\s+(\w+)', line)
        if m:
            cur = m.group(2)
        m = re.search(r'_vslot(\d+)\s*\(\s*\)\s*(?:const\s*)?override', line)
        if m and cur:
            out[(cur, int(m.group(1)))] = '_vslot' + m.group(1)
    return out

def main():
    model = load('model.json')['classes']
    slots = load('slots.json')['classes']
    sizes = load('sizes.json', required=False)
    fwd_slots = load('forwarded.json', required=False)
    macro_src = os.path.join(HERE, '..', 'navi48accel', 'src', 'Navi48Accel.cpp')
    pinned = pinned_macros(macro_src)
    ph = consumer_placeholders(macro_src)

    sdk = {c: sdk_class_header(c) for c in slots if sdk_class_header(c)}
    missing = set()
    for c, info in slots.items():
        sup = info.get('super')
        if sup and not sdk_class_header(sup) and sup not in slots:
            missing.add(sup)
    if missing:
        raise SystemExit('模型缺这些祖先类（无法声明继承链）：%s' % ', '.join(sorted(missing)))

    order, todo, guard = [], set(slots), 0
    while todo and guard < 500:
        prog = False
        for c in sorted(todo):
            sup = slots[c].get('super')
            if sup is None or sdk_class_header(sup) or sup in order:
                order.append(c); todo.discard(c); prog = True
        if not prog:
            raise SystemExit('super 链成环或无法排序：%s' % ', '.join(sorted(todo)))
        guard += 1

    # ---- SDK 签名表 ----
    sdk_sig, sdk_ret, chain_hdrs = {}, {}, set()
    def collect(root):
        seen, cur = [], root
        while cur and cur not in seen:
            seen.append(cur)
            h = sdk.get(cur) or sdk_class_header(cur)
            if not h:
                break
            chain_hdrs.add(h)
            base, sigs = parse_sdk(h)
            for k, v in sigs.items():
                sdk_sig.setdefault(k, v)
                sdk_ret.setdefault((k[0], len(k[1])), v[0])
            cur = base
    for c in slots:
        collect(slots[c].get('super') or 'OSObject')

    # ---- 类型：include / 前向声明 ----
    types = set()
    for c in slots:
        for i, e in slots[c].get('slots', {}).items():
            raw = e.get('args', '') or ''
            if e.get('kind') == 'sdk' and e.get('name'):
                m = re.search(r'\(([^)]*)\)', e['name'])
                if m:
                    raw += ' ' + m.group(1)
            for t in re.findall(r'[A-Za-z_]\w*', raw):
                types.add(t)
    inc, fwd = set(ALWAYS_HEADERS) | chain_hdrs, set()
    for t in sorted(types):
        if t in BUILTIN:
            continue
        h = sdk_class_header(t)
        if h:
            inc.add(h)
            continue
        if is_declared_type(t):
            continue
        fwd.add(t)
    for c in slots:                      # 模型类一律前向声明（见文件头 5）
        if c not in sdk:
            fwd.add(c)
    inc = sorted(h for h in inc if os.path.exists(os.path.join(MKSDK, h)))

    # ---- 阶段一：规划声明 ----
    plan, decl_ret = {}, {}
    for c in order:
        rows = {r['i']: r for r in model[c]['rows']}
        entries = slots[c].get('slots', {})
        decls = []
        for i in sorted(int(k) for k in entries):
            if i in MACRO_SLOTS:
                continue
            e = entries[str(i)]
            row = rows.get(i, {})
            pure = bool(row.get('pure'))
            owner = e.get('owner') or c
            if not owned_by(row, c):
                continue
            if (c, i) in ph:
                # 消费方按槽号手写了 naked thunk：名字无所谓，但必须存在同槽号的虚函数声明
                decls.append((i, 'ph:' + ph[(c, i)], '', '', '', pure)); continue
            if e.get('kind') == 'sdk' and e.get('name'):
                decls.append((i, 'sdk', e['name'], '', '', pure)); continue
            name = e.get('name')
            if not name:
                continue
            args, cv = e.get('args', '') or '', e.get('cv', '') or ''
            key_pin = (san(owner), i)
            key_t, key_n = (name, norm_args(args)), (name, argc(args))
            if key_pin in pinned:
                decls.append((i, 'pin:' + pinned[key_pin][0], name, args, cv, pure))
            elif key_t in sdk_sig:
                ret, sargs, scv = sdk_sig[key_t]
                decls.append((i, 'ret:' + ret, name, sargs, scv, pure))
            elif key_n in sdk_ret:
                decls.append((i, 'ret:' + sdk_ret[key_n], name, args, cv, pure))
            else:
                decls.append((i, 'voidmacro', name, args, cv, pure))
        plan[c] = decls
        for i, kind, name, args, cv, pure in decls:
            decl_ret[(c, i)] = kind

    # ---- 二次传播：本类拥有、但祖先链上同一槽号已有声明的槽是"覆写"，必须与祖先同返回类型 ----
    for c in order:                       # order 是拓扑序：祖先先处理
        sup = slots.get(c, {}).get('super')
        for k, (i, kind, name, args, cv, pure) in enumerate(plan[c]):
            if kind != 'voidmacro':
                continue
            cur, seen = sup, set()
            while cur and cur not in seen:
                seen.add(cur)
                if (cur, i) in decl_ret:
                    plan[c][k] = (i, decl_ret[(cur, i)], name, args, cv, pure)
                    decl_ret[(c, i)] = decl_ret[(cur, i)]
                    break
                cur = slots.get(cur, {}).get('super')

    def resolve(c, i):
        cur, seen = c, set()
        while cur and cur not in seen:
            seen.add(cur)
            if (cur, i) in decl_ret:
                return decl_ret[(cur, i)]
            cur = slots.get(cur, {}).get('super')
        return None

    def ret_token(c, i, owner):
        """这个 (类, 槽) 的返回类型 token：钉死的宏名 / 具体类型 / 兜底宏名。"""
        kind = resolve(c, i)
        if kind is None:
            return 'void'
        if kind.startswith('ph:'):
            return 'void'
        if kind.startswith('pin:'):
            return kind[4:]
        if kind.startswith('ret:'):
            return kind[4:]
        if kind == 'sdk':
            # 找到真正声明这个槽的那个类（沿链上溯），从它的 sdk 签名里取返回类型
            cur, seen = c, set()
            while cur and cur not in seen:
                seen.add(cur)
                e = slots.get(cur, {}).get('slots', {}).get(str(i))
                if e and e.get('kind') == 'sdk' and e.get('name'):
                    return ret_of_sig(e['name'])
                cur = slots.get(cur, {}).get('super')
            return 'void'
        return 'N48_R_%s_%d' % (san(owner), i)

    # ---- 兜底宏：覆盖 slots.json 的**每一个**槽条目（gen_tramp 用 entry.owner 命名）----
    fallback = {}
    for c in order:
        for i, e in (slots[c].get('slots') or {}).items():
            ii = int(i)
            if ii in MACRO_SLOTS:
                continue
            owner = e.get('owner') or c
            m = 'N48_R_%s_%d' % (san(owner), ii)
            kind = resolve(c, ii)
            if kind is None:
                val = 'void'
            elif kind.startswith('pin:'):
                pname = kind[4:]
                val = pinned.get((san(owner), ii), (None, None))[1] or 'void'
                for (pn, pi), (mn, mp) in pinned.items():     # 传播过来的可能是祖先的宏名
                    if mn == pname:
                        val = mp
                        break
            elif kind.startswith('ph:'):
                val = 'void'
            elif kind.startswith('ret:'):
                val = kind[4:]
            elif kind == 'sdk':
                cur, seen, val = c, set(), 'void'
                while cur and cur not in seen:                # 找到真正声明它的那个类的 sdk 签名
                    seen.add(cur)
                    ee = slots.get(cur, {}).get('slots', {}).get(str(ii))
                    if ee and ee.get('kind') == 'sdk' and ee.get('name'):
                        val = ret_of_sig(ee['name'])
                        break
                    cur = slots.get(cur, {}).get('super')
            else:
                val = 'void'
            fallback.setdefault(m, val)

    # ---- 输出 ----
    L = ['// GENERATED by tools/native/ioaccel-layout/gen_header.py — DO NOT EDIT.',
         '// Inputs: generated/{model,slots,sizes,forwarded}.json; the N48_R_* macros are pinned by',
         '// Navi48Accel.cpp BEFORE this header, and the #ifndef fallbacks below mirror this header\'s own',
         '// declarations so that trampoline declarations stay compatible with their base.',
         '// A class declares ONLY the slots it owns (plus its own pure virtuals): a slot\'s mangled name carries',
         '// its defining class, so declaring an inherited method in a subclass would reference the wrong symbol.',
         '// Slots 0/1 (destructors) and 7 (getMetaClass) come from OSDeclareDefaultStructors(C).',
         '#pragma once', '']
    for h in inc:
        L.append('#include <%s>' % h)
    L.append('')
    if fwd:
        L.append('// ---- forward declarations of every reconstructed family class ----')
        for t in sorted(fwd):
            L.append('class %s;' % t)
        L.append('')
    L.append('// ---- return-type fallbacks; the real macros come from Navi48Accel.cpp before this header ----')
    for m in sorted(fallback):
        L.append('#ifndef %s\n#define %s %s\n#endif' % (m, m, fallback[m]))
    L.append('')

    if fwd_slots:
        L.append('// ---- forwarders for the parents\' non-exported slots (the non-trampoline leaves use these) ----')
        for parent in sorted(fwd_slots):
            decs, defs = [], []
            vt = '__ZTV%d%s' % (len(parent), parent)
            for slot in fwd_slots[parent]:
                e = slots.get(parent, {}).get('slots', {}).get(str(slot))
                if not e or not e.get('name'):
                    continue
                args, cv = e.get('args', '') or '', e.get('cv', '') or ''
                ret = ret_token(parent, slot, e.get('owner') or parent)
                decs.append('    virtual %s %s(%s)%s override;' % (ret, e['name'], args, cv))
                defs.append('    __attribute__((naked)) %s Leaf::%s(%s)%s { __asm__("movq %s@GOTPCREL(%%rip), %%rax\\n\\tmovq %d(%%rax), %%rax\\n\\tjmpq *%%rax"); }'
                            % (ret, e['name'], args, cv, vt, 16 + 8 * slot))
            L.append('#define N48_FWD_DECLS_%s \\' % parent)
            L.append(' \\\n'.join(decs) if decs else '    /* none */')
            L.append('#define N48_FWD_DEFS_%s(Leaf) \\' % parent)
            L.append(' \\\n'.join(defs) if defs else '    /* none */')
            L.append('')

    L.append('// ---- family classes the SDK does not declare, reconstructed from the family binaries ----')
    n_cls = 0
    for c in order:
        info = slots[c]
        nslots = model[c]['nslots']
        sz = (sizes.get(c) or {}).get('size')
        if c in sdk:
            L.append('')
            L.append('// %s is declared by the SDK (%s): only the pins are emitted here' % (c, sdk[c]))
            L.append('#define N48_%s_NSLOTS %d' % (c, nslots))
            if sz:
                L.append('enum { N48_%s_SIZE = 0x%x };' % (c, sz))
            continue
        sup = info.get('super') or 'OSObject'
        L.append('')
        L.append('class %s : public %s {' % (c, sup))
        L.append('    OSDeclareDefaultStructors(%s)' % c)
        L.append('public:')
        for i, kind, name, args, cv, pure in plan[c]:
            tail = ' = 0' if pure else ''
            note = ' pure' if pure else ''
            if kind.startswith('ph:'):
                L.append('    virtual void %s();   // slot %d (hand-written override by the consumer)' % (kind[3:], i))
            elif kind == 'sdk':
                L.append('    virtual %s%s;   // slot %d%s' % (name, tail, i, note))
            elif kind.startswith('pin:'):
                L.append('    virtual %s %s(%s)%s%s;   // slot %d (pinned)%s' % (kind[4:], name, args, cv, tail, i, note))
            elif kind == 'voidmacro':
                owner = slots[c].get('slots', {}).get(str(i), {}).get('owner') or c
                L.append('    virtual N48_R_%s_%d %s(%s)%s%s;   // slot %d%s'
                         % (san(owner), i, name, args, cv, tail, i, note))
            else:
                L.append('    virtual %s %s(%s)%s%s;   // slot %d (SDK return type)%s' % (kind[4:], name, args, cv, tail, i, note))
        if not plan[c]:
            L.append('    // (this class introduces no slots of its own)')
        L.append('private:')
        if sz:
            L.append('    uint8_t _opaque[%d > (int)sizeof(%s) ? %d - sizeof(%s) : 1];   // Apple: 0x%x'
                     % (sz, sup, sz, sup, sz))
        else:
            L.append('    // instance size unknown in sizes.json: no padding')
        L.append('};')
        L.append('#define N48_%s_NSLOTS %d' % (c, nslots))
        if sz:
            L.append('enum { N48_%s_SIZE = 0x%x };' % (c, sz))
        n_cls += 1

    out = os.path.join(OUTDIR, 'IOAccelFamily2_decl.h')
    os.makedirs(OUTDIR, exist_ok=True)
    open(out, 'w').write('\n'.join(L) + '\n')
    print('wrote %s' % out)
    print('  declared %d classes (%s) | SDK-docked: %s' % (n_cls, ' '.join(c for c in order if c not in sdk), ' '.join(sorted(sdk))))
    print('  virtuals: %d | fallback macros: %d | SDK sig matches: %d | includes: %d | fwd: %d | FWD parents: %d'
          % (sum(len(v) for v in plan.values()), len(fallback), len(sdk_sig), len(inc), len(fwd), len(fwd_slots)))

if __name__ == '__main__':
    main()
