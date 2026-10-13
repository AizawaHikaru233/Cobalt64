// n48probe.m -- READ-ONLY Objective-C runtime metadata probe for the Navi48Metal plugin.
//
// WHAT IT DOES: dlopens the Metal framework and the *installed* Navi48Metal.bundle (read-only: no
// copy, no install, no MTLDevice is ever created), then, for each (our class, MTL protocol) pair,
// resolves every method of the protocol (required + optional + inherited protocols) and asks WHERE
// the implementation that our class would actually run comes from:
//   * dladdr() on the IMP tells us the image (our bundle vs. the Metal framework vs. elsewhere);
//   * the class chain tells us which class in the hierarchy declares it.
// A method whose only implementation lives in the Metal framework is NOT ours: if Apple's
// implementation is a real one (e.g. the MSL compiler behind -newLibraryWithSource:) that is what we
// want; if it is Apple's abstract-base stub for something a concrete Apple subclass overrides, the
// send raises -doesNotRecognizeSelector: on OUR instance -- which is exactly what happened to
// Unity's MetalHeap::AliasResources (-optimizeContentsForGPUAccess:).
//
// SAFETY: no -[MTLCreateSystemDefaultDevice], no MTLCopyAllDevices, no GPU work, no files written.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#include <stdio.h>

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
                                             @"req": @(req), @"proto": pn}];
        free(md);
    }
    unsigned np = 0;
    Protocol * __unsafe_unretained *pl = protocol_copyProtocolList(p, &np);
    for (unsigned i = 0; i < np; i++) collect_proto(pl[i], seen, out);
    free(pl);
}

// first class in the chain (self..root) that *declares* sel in its own method list
static Class declaring_class(Class c, SEL sel)
{
    for (Class k = c; k; k = class_getSuperclass(k)) {
        unsigned n = 0; Method *ms = class_copyMethodList(k, &n);
        for (unsigned i = 0; i < n; i++) if (method_getName(ms[i]) == sel) { free(ms); return k; }
        free(ms);
    }
    return NULL;
}

static const char *image_of_imp(IMP imp, unsigned long *off)
{
    static char buf[512];
    Dl_info di; memset(&di, 0, sizeof di);
    if (dladdr((void *)imp, &di) && di.dli_fname) {
        if (off) *off = (unsigned long)((const char *)imp - (const char *)di.dli_fbase);
        snprintf(buf, sizeof buf, "%s", di.dli_fname);
    } else { if (off) *off = 0; snprintf(buf, sizeof buf, "?"); }
    return buf;
}

int main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc < 2) { fprintf(stderr, "usage: n48probe <path-to-Navi48Metal-binary> [class:proto ...]\n"); return 2; }
        dlopen("/System/Library/Frameworks/Metal.framework/Versions/A/Metal", RTLD_NOW | RTLD_GLOBAL);
        void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!h) { fprintf(stderr, "FATAL dlopen(%s): %s\n", argv[1], dlerror()); return 3; }
        const char *ourimg = argv[1];

        static const char *pairs[][2] = {
            {"N48RenderEncoder", "MTLRenderCommandEncoder"},
            {"N48ComputeEncoder", "MTLComputeCommandEncoder"},
            {"N48BlitEncoder", "MTLBlitCommandEncoder"},
            {"N48CommandBuffer", "MTLCommandBuffer"},
            {"N48CommandQueue", "MTLCommandQueue"},
            {"N48Texture", "MTLTexture"},
            {"N48Buffer", "MTLBuffer"},
            {"N48RenderPipelineState", "MTLRenderPipelineState"},
            {"N48ComputePipelineState", "MTLComputePipelineState"},
            {"N48SamplerState", "MTLSamplerState"},
            {"N48DepthStencilState", "MTLDepthStencilState"},
            {"N48Fence", "MTLFence"},
            {"N48Heap", "MTLHeap"},
            {"Navi48Device", "MTLDevice"},
            {NULL, NULL}
        };
        // Apple's concrete encoders: a selector implemented by _MTLCommandEncoder AND by the concrete
        // subclass is a stub that the concrete subclass overrides => the base version is a raiser.
        const char *concrete[][2] = {
            {"N48RenderEncoder", "_MTLRenderCommandEncoder"},
            {"N48ComputeEncoder", "_MTLComputeCommandEncoder"},
            {"N48BlitEncoder", "_MTLBlitCommandEncoder"},
            {NULL, NULL}
        };

        printf("# n48probe v1: bundle=%s\n", ourimg);
        for (int i = 0; pairs[i][0]; i++) {
            Class c = objc_getClass(pairs[i][0]);
            Protocol *p = objc_getProtocol(pairs[i][1]);
            printf("## PAIR %s %s class=%s proto=%s\n", pairs[i][0], pairs[i][1], c ? "OK" : "NOTFOUND", p ? "OK" : "NOTFOUND");
            if (!c || !p) continue;
            NSMutableArray *all = [NSMutableArray array];
            NSMutableSet *seen = [NSMutableSet set];
            collect_proto(p, seen, all);
            for (NSDictionary *d in all) {
                NSString *ss = d[@"sel"];
                SEL sel = NSSelectorFromString(ss);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) { printf("MISS\t%s\t%s\t-\t-\t-\t-\t%s\n", pairs[i][0], [ss UTF8String], [d[@"enc"] UTF8String]); continue; }
                IMP imp = method_getImplementation(m);
                unsigned long off = 0;
                const char *img = image_of_imp(imp, &off);
                Class decl = declaring_class(c, sel);
                BOOL ours = strstr(img, "Navi48Metal") != NULL;
                // does it get here through anything other than the class itself?
                const char *ovr = "-";
                for (int k = 0; concrete[k][0]; k++) {
                    if (strcmp(concrete[k][0], pairs[i][0]) != 0) continue;
                    Class cc = objc_getClass(concrete[k][1]);
                    if (cc && declaring_class(cc, sel)) ovr = concrete[k][1];
                }
                printf("%s\t%s\t%s\t%s\t%s\t%s\t%p+0x%lx\t%s\n",
                       ours ? "OWN" : "INHERITED", pairs[i][0], [ss UTF8String],
                       decl ? class_getName(decl) : "?",
                       ours ? "-" : img, ovr, (void *)imp, off,
                       [d[@"enc"] UTF8String]);
            }
        }
        printf("# done\n");
    }
    return 0;
}
