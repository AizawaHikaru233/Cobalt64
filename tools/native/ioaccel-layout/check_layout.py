#!/usr/bin/env python3
"""check_layout.py — gate C 的 host 侧声明检查（不需要链接好的 kext）。

做法：用生成的 IOAccelFamily2_decl.h 编译一个探针 TU（每个族类派生一个带 out-of-line key function 的子类，
Itanium ABI 下 key function 所在 TU 才会 emit vtable），输出汇编（-S），然后解析每个 __ZTVn48probe_<类> 块：
  * 头两个 .quad = offset-to-top 与 typeinfo
  * 之后每个 .quad = 一个槽；编译器最后会补一个 .quad 0 终止符
  * 最末一个非零槽是探针自己加的 key function
于是得到该族类**真实声明出来的 vtable 槽序列**，逐槽与 generated/model.json 比对：
  1. 槽数一致；
  2. 每一槽的符号名落在该槽 mangled 别名集合里（纯虚槽接受 __cxa_pure_virtual / 0）；
  3. rows 的 (lvl,va) 没有 0（gate_compare 会以 kGateFamilyNull 拒绝）。

与其它门的分工（别混淆）：
  * 本脚本 = 声明层：槽数、槽序、每槽符号名（对照从 KDK 二进制提取的模型）。
  * gates/layout_gate_host.py（make 的一部分）= 地址层：把链接后 kext 的重定位解析成的**地址**与模型的
    (lvl,va) 做相等比较，是运行时门的 host 孪生。
  * 运行时 n48_layout_gate()/gate_compare = 在真机上对族元类的 vtable 逐槽比地址。

输出：逐类一行；最后一行 `MATCH ...` 或 `MISMATCH ...`；rc=0 仅当全一致。
"""
import json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, 'generated')
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
MKSDK = os.path.join(REPO, 'src', 'RDNA4FB', 'MacKernelSDK')

def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def parse_vtables(asm, probe_prefix):
    """-> {class: [symbol per slot]}（已去掉头两词、终止符、探针自己的槽）"""
    lines = asm.splitlines()
    out = {}
    i = 0
    while i < len(lines):
        # Itanium ABI 的 vtable 名带长度前缀：__ZTV20n48probe_IOAccelTask
        m = re.match(r'^(__ZTV\d*%s([A-Za-z0-9_]+)):$' % probe_prefix, lines[i])
        if not m:
            i += 1
            continue
        cls, quads = m.group(2), []
        j = i + 1
        while j < len(lines):
            l = lines[j]
            if l and not l[0].isspace() and l.endswith(':'):
                break
            q = l.strip()
            if q.startswith('.quad'):
                quads.append(q[5:].strip())
            j += 1
        slots = quads[2:]                       # 去掉 offset-to-top 与 typeinfo
        if slots and slots[-1] in ('0', ''):    # 编译器补的终止符
            slots.pop()
        if slots:
            slots.pop()                         # 探针自己加的那一槽
        out[cls] = slots
        i = j
    return out

def norm(sym):
    s = sym.strip()
    if s.startswith('0x'):
        return '0'                              # 目标文件里的具体数值（少见）
    return s

def main():
    try:
        model = json.load(open(os.path.join(GEN, 'model.json')))['classes']
    except Exception as e:
        print('MISMATCH: 读不到 model.json (%s)' % e); return 1
    if not os.path.exists(os.path.join(GEN, 'IOAccelFamily2_decl.h')):
        print('MISMATCH: generated/IOAccelFamily2_decl.h 不存在（先跑 gen_header.py）'); return 1

    sdk = sh(['xcrun', '--sdk', 'macosx', '--show-sdk-path']).stdout.strip()
    if not sdk:
        print('MISMATCH: 找不到 macOS SDK'); return 1

    d = tempfile.mkdtemp(prefix='n48chk')
    src, asm = os.path.join(d, 'probe.cpp'), os.path.join(d, 'probe.s')
    body = ['#include "IOAccelFamily2_decl.h"', '']
    for c in sorted(model):
        body.append('struct n48probe_%s : %s { virtual void n48_key(); };' % (c, c))
        body.append('void n48probe_%s::n48_key() {}' % c)
    open(src, 'w').write('\n'.join(body) + '\n')

    cmd = ['clang++', '-arch', 'x86_64', '-std=c++17', '-fno-exceptions', '-fno-rtti',
           '-isysroot', sdk, '-I' + MKSDK + '/Headers', '-I' + GEN,
           '-mmacosx-version-min=11.0', '-DKERNEL', '-DKERNEL_PRIVATE', '-DDRIVER_PRIVATE',
           '-DAPPLE', '-DNeXT', '-nostdinc', '-fno-builtin', '-fno-common', '-fno-stack-protector',
           '-mkernel', '-fapple-kext', '-Os', '-S', src, '-o', asm]
    r = sh(cmd)
    if r.returncode:
        print('MISMATCH: 探针编译失败（生成的声明无法独立编译）')
        print('\n'.join([l for l in r.stderr.splitlines() if 'error' in l][:20]))
        return 1

    # 消费方手写的 _vslot<N>() override 对应的槽：占位符名字是设计约定（槽号才是契约），
    # 所以这些槽只校槽数与位置，不校符号名。数量很少且明确打印出来。
    import importlib.util as _ilu
    _sp = _ilu.spec_from_file_location('gh', __file__.replace('check_layout.py', 'gen_header.py'))
    _gh = _ilu.module_from_spec(_sp); _sp.loader.exec_module(_gh)
    PLACEHOLDER = _gh.consumer_placeholders(__file__.replace('check_layout.py', '../navi48accel/src/Navi48Accel.cpp'))
    skipped = []

    vt = parse_vtables(open(asm).read(), 'n48probe_')
    bad, checked, total = [], 0, 0
    for c in sorted(model):
        want = model[c]['nslots']
        rows = model[c]['rows']
        if c not in vt:
            bad.append('%s: 探针 vtable 未 emit' % c); continue
        got = vt[c]
        checked += 1
        total += want
        if len(got) != want:
            bad.append('%s: 声明出 %d 槽，提取值 %d 槽（差 %+d）' % (c, len(got), want, len(got) - want))
            continue
        for i, sym in enumerate(got):
            s = norm(sym)
            row = rows[i]
            mang = row.get('mangled') or []
            if i in (0, 1):
                # 探针子类必然覆写两个析构槽，所以这里出现的是探针自己的 __ZN...D1Ev/D0Ev。
                # 槽位对齐由"槽数一致 + 其余槽逐槽比对"保证；叶子类（Navi48X）的 0/1 由 gate A 检查
                # （它们必须落在 OSDEFINE_SLOTS 的覆写集里）。
                if i == 0 and 'D1Ev' not in s:
                    bad.append('%s slot 0: 期望析构槽，实得 %s' % (c, s[:40]))
                if i == 1 and 'D0Ev' not in s:
                    bad.append('%s slot 1: 期望析构槽，实得 %s' % (c, s[:40]))
                continue
            if (c, i) in PLACEHOLDER:
                skipped.append('%s slot %d (=%s)' % (c, i, PLACEHOLDER[(c, i)]))
                continue
            if row.get('pure') and (s in ('0', '__cxa_pure_virtual', '___cxa_pure_virtual')):
                continue
            if s not in mang:
                bad.append('%s slot %d: 汇编里是 %s，模型的别名集里没有（%s）'
                           % (c, i, s[:48], ', '.join(m[:28] for m in mang[:3])))
                break
        for r in rows:
            if r.get('lvl') == 0 and r.get('va') == 0:
                bad.append('%s: 槽 %d 的 (lvl,va) 为 0' % (c, r['i'])); break
    for b in bad:
        print('  FAIL %s' % b)
    if bad:
        print('MISMATCH: %d 处不一致（检查 %d 类）' % (len(bad), checked))
        return 1
    print('MATCH: %d classes, %d slots — declarations reproduce the extracted vtables (slot count, order and per-slot symbol)' % (checked, total))
    if skipped:
        print('  (slot count still checked; symbol name not compared for %d hand-written placeholder slot(s): %s)'
              % (len(skipped), ', '.join(skipped)))
    return 0

if __name__ == '__main__':
    sys.exit(main())
