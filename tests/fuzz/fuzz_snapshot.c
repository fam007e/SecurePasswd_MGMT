/* libFuzzer harness for the sync snapshot parser.
 *
 * Feeds fully attacker-controlled bytes into sync_snapshot_deserialize and,
 * on success, into the merge engine and the serializer (round-trip). Targets
 * out-of-bounds reads/writes, use-after-free, int overflows in length
 * arithmetic and unbounded allocations.
 *
 * Build:  cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DENABLE_FUZZING=ON \
 *              -DCMAKE_C_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer"
 *         cmake --build build-fuzz --target fuzz_snapshot
 * Run:    ./build-fuzz/tests/fuzz_snapshot corpus/
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sync_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Keep exec time bounded: the parser rejects >1M entries anyway. */
    if (size > 256 * 1024) return 0;

    sync_entry_t *entries = NULL;
    sync_tombstone_t *tombs = NULL;
    int ne = 0, nt = 0;

    if (sync_snapshot_deserialize(data, size, &entries, &ne, &tombs, &nt) == 0) {
        /* Merge parsed (attacker-shaped) records against an empty local
         * vault — exercises identity matching, winner selection and the
         * report allocation paths on hostile input. */
        sync_merge_report_t rep;
        if (sync_merge_vaults(NULL, 0, entries, ne, NULL, 0, tombs, nt, &rep) == 0) {
            sync_merge_report_free(&rep);
        }

        /* Self-merge: the same hostile records on BOTH sides. Exercises
         * the local-vs-remote winner selection, case-insensitive identity
         * collision and tie-break paths that the empty-local merge skips. */
        sync_merge_report_t rep2;
        if (sync_merge_vaults(entries, ne, entries, ne, tombs, nt, tombs, nt, &rep2) == 0) {
            sync_merge_report_free(&rep2);
        }

        /* Re-serialization must never crash on anything the parser accepted. */
        uint8_t *buf = NULL;
        size_t buf_len = 0;
        if (sync_snapshot_serialize(entries, ne, tombs, nt, &buf, &buf_len) == 0 && buf) {
            memset(buf, 0, buf_len);
            free(buf);
        }

        sync_entries_free(entries, ne);
        sync_tombstones_free(tombs, nt);
    }
    return 0;
}
