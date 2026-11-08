/* libFuzzer harness for the OpenPGP key-store parser and merge.
 *
 * Feeds fully attacker-controlled bytes into sync_gpg_deserialize
 * (SPSNAP03 sections) and, on success, into sync_merge_gpg_keys — as a
 * hostile remote store, a self-merge, and against snapshot-parsed
 * tombstones (service == "GPG" steers the gpg tombstone paths). Also
 * encodes the parser contract the merge relies on: a successfully
 * deserialized key store never contains a NULL label, and anything
 * accepted must re-serialize to an identical count.
 *
 * Build:  cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DENABLE_FUZZING=ON \
 *              -DCMAKE_C_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer"
 *         cmake --build build-fuzz --target fuzz_gpgmerge
 * Run:    ./build-fuzz/tests/fuzz_gpgmerge corpus/
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sync_protocol.h"

/* Parser contract: surviving keys always carry a label. The merge guards
 * defensively (NULL-label keys never match), but a NULL label surviving a
 * successful parse would mean the serializer/parser pair drifted apart. */
static void check_labels_nonnull(const sync_gpg_key_t *keys, int count) {
    for (int i = 0; i < count; i++) {
        if (keys[i].label == NULL) abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Keep exec time bounded, matching fuzz_snapshot. */
    if (size < 2 || size > 256 * 1024) return 0;

    /* First half: "local" bytes, second half: "remote" bytes. The
     * deserializers only write their outputs on success. */
    size_t half = size / 2;

    sync_gpg_key_t *lk = NULL, *rk = NULL;
    int ln = 0, rn = 0;
    if (sync_gpg_deserialize(data, half, &lk, &ln) == 0) {
        check_labels_nonnull(lk, ln);
    }
    if (sync_gpg_deserialize(data + half, size - half, &rk, &rn) == 0) {
        check_labels_nonnull(rk, rn);
    }

    /* Tombstones parsed from the same hostile bytes. */
    sync_entry_t *le = NULL, *re = NULL;
    sync_tombstone_t *lt = NULL, *rt = NULL;
    int ln_e = 0, ln_t = 0, rn_e = 0, rn_t = 0;
    if (sync_snapshot_deserialize(data, half, &le, &ln_e, &lt, &ln_t) != 0) {
        le = NULL; lt = NULL; ln_e = 0; ln_t = 0;
    }
    if (sync_snapshot_deserialize(data + half, size - half, &re, &rn_e, &rt, &rn_t) != 0) {
        re = NULL; rt = NULL; rn_e = 0; rn_t = 0;
    }

    /* Hostile store vs hostile store, tombstones cross-applied. */
    sync_gpg_merge_report_t rep;
    if (sync_merge_gpg_keys(lk, ln, rk, rn, lt, ln_t, rt, rn_t, &rep) == 0) {
        if (rep.result_count < 0) abort();
        sync_gpg_merge_report_free(&rep);
    }

    /* Self-merge: identical hostile stores on both sides. */
    sync_gpg_merge_report_t rep2;
    if (sync_merge_gpg_keys(lk, ln, lk, ln, lt, ln_t, lt, ln_t, &rep2) == 0) {
        sync_gpg_merge_report_free(&rep2);
    }

    /* Round-trip: anything accepted must re-serialize and re-parse to the
     * same key count. Then free the local store. */
    if (lk) {
        uint8_t *buf = NULL;
        size_t bl = 0;
        if (sync_gpg_serialize(lk, ln, &buf, &bl) == 0 && buf) {
            sync_gpg_key_t *out = NULL;
            int on = 0;
            if (sync_gpg_deserialize(buf, bl, &out, &on) == 0) {
                if (on != ln) abort();
                sync_gpg_keys_free(out, on);
            }
            memset(buf, 0, bl);
            free(buf);
        }
        sync_gpg_keys_free(lk, ln);
        lk = NULL;
    }

    if (rk) sync_gpg_keys_free(rk, rn);
    if (le) sync_entries_free(le, ln_e);
    if (re) sync_entries_free(re, rn_e);
    if (lt) sync_tombstones_free(lt, ln_t);
    if (rt) sync_tombstones_free(rt, rn_t);
    return 0;
}
