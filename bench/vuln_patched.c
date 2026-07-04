/*
 * LUCENT M3 fixture — the PATCHED half of the patch-diff pair.
 *
 * VENDORED from the Bug Museum so LUCENT is self-contained on the target VM.
 * Source of truth / keep in sync:
 *   BugMuseum/0_stack-overflow/variant-01-strcpy/src_patched.c
 * Body is byte-for-byte the museum fixture; only this provenance header is added.
 *
 * This is the POST-patch build (`patched.exe`) that `vuln.exe` (pre-patch,
 * unbounded `strcpy`) is diffed against. The single security-relevant delta is
 * `strcpy -> strncpy(..., sizeof buf - 1)` + an explicit NUL terminator — i.e.
 * the fix bounds the copy to the destination. ghidriff over (vuln.exe, patched.exe)
 * surfaces exactly that change; the agent infers the pre-patch bug from it.
 *
 * Build with the SAME flags as vuln.exe so the diff is signal-only:
 *   LUCENT_BUILD=patched  bench\build.bat   ->  /Zi /Od /GS-  ->  patched.exe
 *
 * Self-authored / museum-sourced == CONTAMINATED: proves the tool + loop, not
 * discovery capability. Tag any Task built on it contaminated=True.
 */
#include <string.h>

/* Buffer size is a compile knob (default 16 == museum; LUCENT_BUILD=bigpatched
 * passes /DBUFSZ=4096) so this stays the patched half of the big-buffer probe
 * pair. The bound tracks the buffer automatically via `sizeof buf`. */
#ifndef BUFSZ
#define BUFSZ 16
#endif

/* PATCHED — the stack overflow is fixed by bounding the copy to the destination:
 * at most sizeof(buf)-1 bytes, then an explicit NUL terminator. */
void vuln(const char *input) {
    char buf[BUFSZ];
    strncpy(buf, input, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
