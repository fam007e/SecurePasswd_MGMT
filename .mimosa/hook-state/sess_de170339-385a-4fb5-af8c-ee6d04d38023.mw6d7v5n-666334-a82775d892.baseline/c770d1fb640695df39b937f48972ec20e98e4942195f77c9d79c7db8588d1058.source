/* libFuzzer harness for the AEAD frame parser.
 *
 * Derives one session per process (handshake is expensive; per-exec random
 * keys add no coverage) and feeds attacker-controlled wire bytes to
 * sync_frame_decrypt with every expected frame type. Targets length-field
 * arithmetic, AAD/nonce handling and tag verification paths for OOB and
 * UAF bugs.
 *
 * Build/run: see fuzz_snapshot.c.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "sync_protocol.h"

static sync_session_t session;
static int session_ready = 0;

static void init_session_once(void) {
    uint8_t psk[SYNC_PSK_LEN];
    uint8_t c_pub[SYNC_EPHEMERAL_LEN], c_priv[SYNC_EPHEMERAL_LEN];
    uint8_t s_pub[SYNC_EPHEMERAL_LEN], s_priv[SYNC_EPHEMERAL_LEN];

    RAND_bytes(psk, sizeof(psk));
    if (sync_ephemeral_keygen(c_pub, c_priv) != 0) return;
    if (sync_ephemeral_keygen(s_pub, s_priv) != 0) return;
    if (sync_session_derive(SYNC_ROLE_SERVER, psk, c_pub, s_pub, s_priv, &session) != 0) {
        return;
    }
    session_ready = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!session_ready) {
        init_session_once();
        if (!session_ready) return 0;
    }
    if (size < 6) return 0; /* smallest plausible frame: 1 type + 5 header */

    /* The fuzzer picks the expected type; every type gets exercised. */
    uint8_t expected = (uint8_t)(data[0] % 5 + 1);

    /* Small receive buffer forces the payload-length checks; frames with
     * larger payloads are rejected before decryption (cheap path). */
    uint8_t out[2048];
    size_t out_len = 0;
    if (sync_frame_decrypt(&session, expected,
                           data + 1, size - 1,
                           out, sizeof(out), &out_len) == 0) {
        /* Decrypted payload is attacker-influenced plaintext; parse it as a
         * snapshot too, chaining the two parsers like the real server does. */
        sync_entry_t *entries = NULL;
        sync_tombstone_t *tombs = NULL;
        int ne = 0, nt = 0;
        if (sync_snapshot_deserialize(out, out_len, &entries, &ne, &tombs, &nt) == 0) {
            sync_entries_free(entries, ne);
            sync_tombstones_free(tombs, nt);
        }
    }
    return 0;
}
