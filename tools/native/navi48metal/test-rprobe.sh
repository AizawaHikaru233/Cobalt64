#!/bin/zsh
# test-rprobe.sh -- build and run the two READ-ONLY runtime-metadata probes (build 34, DEPLOY-LOG step 63).
#
#   test-rtprobe.m : for every method of every MTL protocol our classes claim to conform to, WHERE does
#                    the implementation the class would actually run come from?  OURS / inherited from
#                    the Metal framework (the census cannot see the difference: it asks
#                    -class_respondsToSelector:, which is YES for an inherited raiser too).
#   test-rraise.m  : for the VOID methods satisfied only by inheritance, does that inherited
#                    implementation RAISE, RETURN, CRASH or HANG?  Measured in a forked child that
#                    sends the message to a raw (never -init'ed) instance of a stub subclass of the
#                    SAME Apple superclass, with a -doesNotRecognizeSelector: override that _exit(42)s.
#                    RAISES is what killed Chained Echoes (Unity MetalHeap::AliasResources).
#
# Neither probe creates an MTLDevice, calls MTLCopyAllDevices or does any GPU work; each dlopens the
# Metal framework and one Navi48Metal binary READ-ONLY, so they can be pointed at the installed bundle
# or at build/Navi48Metal.bundle without installing anything.
#     zsh test-rprobe.sh [<Navi48Metal binary>]        (default: the installed bundle)
set -u
D="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-/Library/GPUBundles/Navi48Metal.bundle/Contents/MacOS/Navi48Metal}"
[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 1; }
W="$(mktemp -d "${TMPDIR:-/tmp}/n48rprobe.XXXXXX")"
trap 'rm -rf "$W"' EXIT
clang -fobjc-arc -O1 -o "$W/test-rtprobe" "$D/test-rtprobe.m" -framework Foundation || exit 1
clang -fobjc-arc -O1 -o "$W/test-rraise"  "$D/test-rraise.m"  -framework Foundation || exit 1
echo "== test-rtprobe  $BIN"
"$W/test-rtprobe" "$BIN" > "$W/rt.tsv"
printf '   OWN=%s  INHERITED=%s  MISS=%s\n' \
  "$(grep -c '^OWN' "$W/rt.tsv")" "$(grep -c '^INHERITED' "$W/rt.tsv")" "$(grep -c '^MISS' "$W/rt.tsv")"
echo "   inherited-implementation selectors per class:"
awk -F'\t' '$1=="INHERITED"{print $2}' "$W/rt.tsv" | sort | uniq -c | sort -rn | sed 's/^/     /'
echo "== test-rraise  (verdicts over inherited VOID methods, deduplicated)"
"$W/test-rraise" "$BIN" > "$W/ra.tsv" 2>/dev/null
awk -F'\t' '$1=="INH"{print $2"\t"$3"\t"$4}' "$W/ra.tsv" | sort -u > "$W/ra.uniq"
awk -F'\t' '{c[$1]++} END{for(k in c) printf "     %s=%d\n", k, c[k]}' "$W/ra.uniq" | sort
echo "   the five selectors build 34 implements (expect NONE here on a build-34 binary):"
grep -E 'optimizeContents|insertDebugSignpost' "$W/ra.uniq" | grep N48BlitEncoder | sed 's/^/     /' || echo "     none"
echo "   the commands used, verbatim:"
echo "     clang -fobjc-arc -O1 -o test-rtprobe test-rtprobe.m -framework Foundation && ./test-rtprobe $BIN"
echo "     clang -fobjc-arc -O1 -o test-rraise  test-rraise.m  -framework Foundation && ./test-rraise $BIN"
echo "(the probes print a TSV table on stdout; set N48RPROBE_KEEP=1 to keep $W)"
