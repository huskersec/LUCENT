/*
 * LUCENT M2 fixture — the stack-overflow baseline.
 *
 * VENDORED from the Bug Museum so LUCENT is self-contained on the target VM
 * (BugMuseum is not checked out there). Source of truth / keep in sync:
 *   BugMuseum/0_stack-overflow/variant-01-strcpy/src.c
 * Body is byte-for-byte the museum fixture; only this provenance header is added
 * (comments are stripped from the build, so patch-diffs against the museum
 * binaries are unaffected).
 *
 * Self-authored / museum-sourced == CONTAMINATED: proves the oracle PLUMBING,
 * not discovery capability. Tag any Task built on it contaminated=True.
 *
 * Build: m2/build.bat  ->  cl /Zi /Od /GS-  ->  vuln.exe + vuln.pdb
 *   /GS-  no stack cookie: the overflow overwrites the saved return address, so
 *         `ret` faults with an ACCESS VIOLATION the oracle's `sxe av` catches.
 * The payload is argv[1] (a string), NOT a file. No page heap (stack, not heap).
 */
#include <string.h>

/* Classic stack buffer overflow.
 * buf is 16 bytes; strcpy copies until the NUL in `input`,
 * with no regard for the destination size. An input longer
 * than 15 bytes (+NUL) overruns buf and walks up the frame
 * toward saved RBP and the return address. */
void vuln(const char *input) {
    char buf[16];
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
