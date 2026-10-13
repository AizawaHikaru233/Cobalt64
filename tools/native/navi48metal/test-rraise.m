// n48probe2.m -- READ-ONLY: does an Apple-inherited implementation RAISE, RETURN or CRASH?
//
// WHY (evidence): Chained Echoes (Unity 2020.3.36f1) died on
//   #11 -[_MTLCommandEncoder optimizeContentsForGPUAccess:]  (Metal framework)
//   #10 -[N48BlitEncoder doesNotRecognizeSelector:]
//   #3  objc_exception_throw
// i.e. the plugin never implements that selector, the message is dispatched to Apple's abstract
// base class _MTLCommandEncoder, and Apple's implementation answers by raising -- so neither the
// census (class_respondsToSelector says YES, it is "implemented") nor the build-31 forwarding net
// (forwardInvocation: only runs when NO class implements the selector) can see it.
//
// THIS PROBE measures that for every MTL protocol method our classes satisfy only by inheritance.
// Method: build a stub subclass of the SAME Apple superclass whose only override is
// -doesNotRecognizeSelector: (it _exit(42)), fork one child per selector, send the message to a raw
// (zero-filled, never -init'ed) instance with zero arguments and record how the child died.
//   exit 42 -> RAISES (inherited implementation refuses: a landmine for a client that calls it)
//   exit 0  -> RETURNS (the inherited implementation is real)
//   signal  -> CRASHES on a zero object (also unusable)
//
// SAFETY: no MTLDevice, no MTLCopyAllDevices, no GPU work, no files written; each test runs in a
// forked child that can only kill itself. The Metal framework and the installed bundle are dlopen'ed
// READ-ONLY.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static void collect_proto(Protocol *p, NSMutableSet *seen, NSMutableArray *out)
{
    NSString *pn = NSStringFromProtocol(p);
    if (!pn || [pn isEqualToString:@"NSObject"] || [seen containsObject:pn]) return;
    [seen addObject:pn];
    for (int req = 1; req >= 0; req--) {
        unsigned n = 0;
        struct objc_method_description *md = protocol_copyMethodDescriptionList(p, req ? YES : NO, YES, &n);
        for (unsigned i = 0; i < n; i++)
            if (md[i].name) [out addObject:@{@"sel": NSStringFromSelector(md[i].name),
                                             @"enc": md[i].types ? [NSString stringWithUTF8String:md[i].types] : @"",
                                             @"req": @(req)}];
        free(md);
    }
    unsigned np = 0;
    Protocol * __unsafe_unretained *pl = protocol_copyProtocolList(p, &np);
    for (unsigned i = 0; i < np; i++) collect_proto(pl[i], seen, out);
    free(pl);
}

static Class declaring_class(Class c, SEL sel)
{
    for (Class k = c; k; k = class_getSuperclass(k)) {
        unsigned n = 0; Method *ms = class_copyMethodList(k, &n);
        for (unsigned i = 0; i < n; i++) if (method_getName(ms[i]) == sel) { free(ms); return k; }
        free(ms);
    }
    return NULL;
}
static const char *image_of_imp(IMP imp)
{
    static char buf[512]; Dl_info di; memset(&di, 0, sizeof di);
    if (dladdr((void *)imp, &di) && di.dli_fname) snprintf(buf, sizeof buf, "%s", di.dli_fname);
    else snprintf(buf, sizeof buf, "?");
    return buf;
}

static Class g_dummy;
static void dnr_override(id self, SEL _cmd, SEL sel) { (void)self; (void)_cmd; (void)sel; _exit(42); }

int main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc < 2) { fprintf(stderr, "usage: n48probe2 <Navi48Metal-binary>\n"); return 2; }
        dlopen("/System/Library/Frameworks/Metal.framework/Versions/A/Metal", RTLD_NOW | RTLD_GLOBAL);
        if (!dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)) { fprintf(stderr, "FATAL: %s\n", dlerror()); return 3; }

        static const char *pairs[][3] = {
            {"N48RenderEncoder",  "MTLRenderCommandEncoder",  "_MTLCommandEncoder"},
            {"N48ComputeEncoder", "MTLComputeCommandEncoder", "_MTLCommandEncoder"},
            {"N48BlitEncoder",    "MTLBlitCommandEncoder",    "_MTLCommandEncoder"},
            {"N48CommandBuffer",  "MTLCommandBuffer",         "_MTLCommandBuffer"},
            {"N48CommandQueue",   "MTLCommandQueue",          "_MTLCommandQueue"},
            {"N48Texture",        "MTLTexture",               "_MTLResource"},
            {"N48Buffer",         "MTLBuffer",                "_MTLResource"},
            {"N48RenderPipelineState", "MTLRenderPipelineState", "_MTLRenderPipelineState"},
            {"N48Heap",           "MTLHeap",                  "_MTLHeap"},
            {NULL, NULL, NULL}
        };
        printf("# n48probe2 v1 bundle=%s pid=%d\n", argv[1], getpid());
        for (int i = 0; pairs[i][0]; i++) {
            Class c = objc_getClass(pairs[i][0]);
            Protocol *p = objc_getProtocol(pairs[i][1]);
            Class sup = objc_getClass(pairs[i][2]);
            printf("## PAIR %s %s super=%s class=%d proto=%d\n", pairs[i][0], pairs[i][1], pairs[i][2], c != nil, p != nil);
            if (!c || !p || !sup) continue;
            char dn[128]; snprintf(dn, sizeof dn, "N48ProbeStub_%s", pairs[i][0]);
            Class dummy = objc_allocateClassPair(sup, dn, 0);
            if (!dummy) { printf("# cannot allocate stub subclass of %s\n", pairs[i][2]); continue; }
            class_addMethod(dummy, @selector(doesNotRecognizeSelector:), (IMP)dnr_override, "v@::");
            objc_registerClassPair(dummy);
            g_dummy = dummy;

            NSMutableArray *all = [NSMutableArray array]; NSMutableSet *seen = [NSMutableSet set];
            collect_proto(p, seen, all);
            for (NSDictionary *d in all) {
                NSString *ss = d[@"sel"];
                SEL sel = NSSelectorFromString(ss);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;                                     // MISS is the census's job
                const char *enc = [d[@"enc"] UTF8String];
                if (enc[0] != 'v') continue;                          // only void returns are sent safely
                IMP imp = method_getImplementation(m);
                if (strstr(image_of_imp(imp), "Navi48Metal")) continue; // ours: not a landmine
                Class decl = declaring_class(c, sel);
                fflush(NULL);   // empty the buffer first: a child that dies must not flush the parent's copy
                pid_t pid = fork();
                if (pid == 0) {
                    signal(SIGSEGV, SIG_DFL);
                    alarm(2);   // a client that would block forever is reported as HANGS, not waited for
                    id obj = class_createInstance(dummy, 0);
                    void (*fn)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
                    fn = (void (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend;
                    fn(obj, sel, 0, 0, 0, 0, 0, 0, 0, 0);
                    _exit(0);
                }
                int st = 0; waitpid(pid, &st, 0);
                const char *verdict = "UNKNOWN";
                if (WIFEXITED(st)) verdict = (WEXITSTATUS(st) == 42) ? "RAISES" : (WEXITSTATUS(st) == 0 ? "RETURNS" : "EXITED");
                else if (WIFSIGNALED(st)) verdict = (WTERMSIG(st) == SIGALRM) ? "HANGS" : "CRASHES";
                printf("INH\t%s\t%s\t%s\t%s\tdecl=%s\t%s\n", verdict, pairs[i][0], [ss UTF8String],
                       image_of_imp(imp), decl ? class_getName(decl) : "?", enc);
            }
        }
        printf("# done\n");
    }
    return 0;
}
