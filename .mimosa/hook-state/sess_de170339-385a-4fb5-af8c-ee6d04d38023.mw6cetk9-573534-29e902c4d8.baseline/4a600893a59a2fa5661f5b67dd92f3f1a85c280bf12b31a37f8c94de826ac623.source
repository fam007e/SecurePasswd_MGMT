/* Tests for the v2 2-way sync protocol: handshake, AEAD framing (including
 * replay/re-order rejection), snapshot serialization round-trip and the
 * deterministic merge engine. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <openssl/rand.h>
#include "core/sync_protocol.h"

/* ---------- handshake ---------- */

static void test_ct_equal(void **state) {
    (void)state;
    const uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t b[8];
    memcpy(b, a, sizeof(a));
    assert_int_equal(sync_ct_equal(a, b, sizeof(a)), 1);
    assert_int_equal(sync_ct_equal(a, a, sizeof(a)), 1);

    b[7] ^= 0x01;
    assert_int_equal(sync_ct_equal(a, b, sizeof(a)), 0);
    b[0] ^= 0x01; /* two differing bytes still rejected */
    assert_int_equal(sync_ct_equal(a, b, sizeof(a)), 0);
    assert_int_equal(sync_ct_equal(NULL, b, sizeof(a)), 0);
}

static void test_handshake_roundtrip(void **state) {
    (void)state;
    uint8_t psk[SYNC_PSK_LEN];
    assert_int_equal(RAND_bytes(psk, sizeof(psk)), 1);

    uint8_t c_pub[SYNC_EPHEMERAL_LEN], c_priv[SYNC_EPHEMERAL_LEN];
    uint8_t s_pub[SYNC_EPHEMERAL_LEN], s_priv[SYNC_EPHEMERAL_LEN];
    assert_int_equal(sync_ephemeral_keygen(c_pub, c_priv), 0);
    assert_int_equal(sync_ephemeral_keygen(s_pub, s_priv), 0);

    sync_session_t client, server;
    assert_int_equal(sync_session_derive(SYNC_ROLE_CLIENT, psk, c_pub, s_pub, c_priv, &client), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_SERVER, psk, c_pub, s_pub, s_priv, &server), 0);

    /* Both ends must derive identical traffic keys and the same transcript. */
    assert_memory_equal(client.c2s_key, server.c2s_key, SYNC_KEY_LEN);
    assert_memory_equal(client.s2c_key, server.s2c_key, SYNC_KEY_LEN);
    assert_memory_equal(client.c2s_iv, server.c2s_iv, SYNC_IV_LEN);
    assert_memory_equal(client.s2c_iv, server.s2c_iv, SYNC_IV_LEN);
    assert_memory_equal(client.transcript_hash, server.transcript_hash, 32);

    sync_session_zero(&client);
    sync_session_zero(&server);
}

static void test_handshake_wrong_psk_fails_confirmation(void **state) {
    (void)state;
    uint8_t psk[SYNC_PSK_LEN], psk_evil[SYNC_PSK_LEN];
    assert_int_equal(RAND_bytes(psk, sizeof(psk)), 1);
    assert_int_equal(RAND_bytes(psk_evil, sizeof(psk_evil)), 1);

    uint8_t c_pub[SYNC_EPHEMERAL_LEN], c_priv[SYNC_EPHEMERAL_LEN];
    uint8_t s_pub[SYNC_EPHEMERAL_LEN], s_priv[SYNC_EPHEMERAL_LEN];
    assert_int_equal(sync_ephemeral_keygen(c_pub, c_priv), 0);
    assert_int_equal(sync_ephemeral_keygen(s_pub, s_priv), 0);

    sync_session_t client, server;
    assert_int_equal(sync_session_derive(SYNC_ROLE_CLIENT, psk, c_pub, s_pub, c_priv, &client), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_SERVER, psk_evil, c_pub, s_pub, s_priv, &server), 0);

    /* Different PSK => different keys => frames must not authenticate. */
    assert_memory_not_equal(client.c2s_key, server.c2s_key, SYNC_KEY_LEN);

    uint8_t frame[128], plain[128];
    size_t flen = 0, plen = 0;
    assert_int_equal(sync_frame_encrypt(&client, SYNC_FRAME_CONFIRM,
                                        client.transcript_hash, 32,
                                        frame, sizeof(frame), &flen), 0);
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_CONFIRM,
                                        frame, flen, plain, sizeof(plain), &plen), -1);

    sync_session_zero(&client);
    sync_session_zero(&server);
}

/* ---------- framing ---------- */

static void test_frame_roundtrip_and_direction(void **state) {
    (void)state;
    uint8_t psk[SYNC_PSK_LEN];
    assert_int_equal(RAND_bytes(psk, sizeof(psk)), 1);

    uint8_t c_pub[SYNC_EPHEMERAL_LEN], c_priv[SYNC_EPHEMERAL_LEN];
    uint8_t s_pub[SYNC_EPHEMERAL_LEN], s_priv[SYNC_EPHEMERAL_LEN];
    sync_session_t client, server;
    assert_int_equal(sync_ephemeral_keygen(c_pub, c_priv), 0);
    assert_int_equal(sync_ephemeral_keygen(s_pub, s_priv), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_CLIENT, psk, c_pub, s_pub, c_priv, &client), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_SERVER, psk, c_pub, s_pub, s_priv, &server), 0);

    const char *msg = "hello desktop";
    uint8_t frame[128], plain[128];
    size_t flen = 0, plen = 0;
    assert_int_equal(sync_frame_encrypt(&client, SYNC_FRAME_SNAPSHOT,
                                        (const uint8_t *)msg, strlen(msg),
                                        frame, sizeof(frame), &flen), 0);
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT,
                                        frame, flen, plain, sizeof(plain), &plen), 0);
    assert_int_equal(plen, strlen(msg));
    assert_memory_equal(plain, msg, plen);

    /* Sequence numbers must advance. */
    assert_int_equal(client.send_seq, 1);
    assert_int_equal(server.recv_seq, 1);

    /* Tampered payload must fail authentication. */
    frame[flen - 1] ^= 0x01;
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT,
                                        frame, flen, plain, sizeof(plain), &plen), -1);

    sync_session_zero(&client);
    sync_session_zero(&server);
}

static void test_frame_replay_rejected(void **state) {
    (void)state;
    uint8_t psk[SYNC_PSK_LEN];
    assert_int_equal(RAND_bytes(psk, sizeof(psk)), 1);

    uint8_t c_pub[SYNC_EPHEMERAL_LEN], c_priv[SYNC_EPHEMERAL_LEN];
    uint8_t s_pub[SYNC_EPHEMERAL_LEN], s_priv[SYNC_EPHEMERAL_LEN];
    sync_session_t client, server;
    assert_int_equal(sync_ephemeral_keygen(c_pub, c_priv), 0);
    assert_int_equal(sync_ephemeral_keygen(s_pub, s_priv), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_CLIENT, psk, c_pub, s_pub, c_priv, &client), 0);
    assert_int_equal(sync_session_derive(SYNC_ROLE_SERVER, psk, c_pub, s_pub, s_priv, &server), 0);

    uint8_t f1[64], f2[64], plain[64];
    size_t l1 = 0, l2 = 0, plen = 0;
    const char *m1 = "one", *m2 = "two";
    assert_int_equal(sync_frame_encrypt(&client, SYNC_FRAME_SNAPSHOT, (const uint8_t *)m1, 3, f1, sizeof(f1), &l1), 0);
    assert_int_equal(sync_frame_encrypt(&client, SYNC_FRAME_SNAPSHOT, (const uint8_t *)m2, 3, f2, sizeof(f2), &l2), 0);

    /* Out-of-order delivery (f2 before f1) must be rejected. */
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT, f2, l2, plain, sizeof(plain), &plen), -1);
    /* Correct order works. */
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT, f1, l1, plain, sizeof(plain), &plen), 0);
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT, f2, l2, plain, sizeof(plain), &plen), 0);
    /* Replay of an already-consumed frame must be rejected. */
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT, f1, l1, plain, sizeof(plain), &plen), -1);

    /* Wrong expected type must be rejected. */
    assert_int_equal(sync_frame_encrypt(&client, SYNC_FRAME_ACK, (const uint8_t *)m1, 3, f1, sizeof(f1), &l1), 0);
    assert_int_equal(sync_frame_decrypt(&server, SYNC_FRAME_SNAPSHOT, f1, l1, plain, sizeof(plain), &plen), -1);

    sync_session_zero(&client);
    sync_session_zero(&server);
}

/* ---------- snapshot serialization ---------- */

static void test_snapshot_roundtrip(void **state) {
    (void)state;
    sync_entry_t entries[2];
    sync_entry_init(&entries[0]);
    entries[0].service = strdup("GitHub");
    entries[0].username = strdup("alice@example.com");
    entries[0].password = strdup("s3cret!");
    entries[0].totp_secret = strdup("JBSWY3DPEHPK3PXP");
    entries[0].recovery_codes = strdup("1111\n2222");
    entries[0].updated_at = 1000;
    sync_entry_init(&entries[1]);
    entries[1].service = strdup("Bank");
    entries[1].username = strdup("bob");
    entries[1].password = strdup("hunter2");
    entries[1].totp_secret = strdup("");
    entries[1].recovery_codes = strdup("");
    entries[1].updated_at = 2000;

    sync_tombstone_t tombs[1];
    tombs[0].service = strdup("Old");
    tombs[0].username = strdup("gone");
    tombs[0].deleted_at = 1500;

    uint8_t *buf = NULL;
    size_t len = 0;
    assert_int_equal(sync_snapshot_serialize(entries, 2, tombs, 1, &buf, &len), 0);
    assert_non_null(buf);

    sync_entry_t *out_e = NULL;
    sync_tombstone_t *out_t = NULL;
    int ne = 0, nt = 0;
    assert_int_equal(sync_snapshot_deserialize(buf, len, &out_e, &ne, &out_t, &nt), 0);
    assert_int_equal(ne, 2);
    assert_int_equal(nt, 1);
    assert_string_equal(out_e[0].service, "GitHub");
    assert_string_equal(out_e[0].password, "s3cret!");
    assert_string_equal(out_e[0].totp_secret, "JBSWY3DPEHPK3PXP");
    assert_string_equal(out_e[0].recovery_codes, "1111\n2222");
    assert_int_equal(out_e[0].updated_at, 1000);
    assert_string_equal(out_e[1].service, "Bank");
    assert_int_equal(out_e[1].updated_at, 2000);
    assert_string_equal(out_t[0].service, "Old");
    assert_int_equal(out_t[0].deleted_at, 1500);

    /* Empty vault round-trips too. */
    uint8_t *buf2 = NULL;
    size_t len2 = 0;
    sync_entry_t *oe2 = NULL;
    sync_tombstone_t *ot2 = NULL;
    int ne2 = 0, nt2 = 0;
    assert_int_equal(sync_snapshot_serialize(NULL, 0, NULL, 0, &buf2, &len2), 0);
    assert_int_equal(sync_snapshot_deserialize(buf2, len2, &oe2, &ne2, &ot2, &nt2), 0);
    assert_int_equal(ne2, 0);
    assert_int_equal(nt2, 0);

    /* Trailing garbage must be rejected. */
    uint8_t *evil = malloc(len + 1);
    memcpy(evil, buf, len);
    evil[len] = 0x41;
    sync_entry_t *oe3 = NULL;
    sync_tombstone_t *ot3 = NULL;
    int ne3 = 0, nt3 = 0;
    assert_int_equal(sync_snapshot_deserialize(evil, len + 1, &oe3, &ne3, &ot3, &nt3), -1);
    free(evil);

    if (buf2) { memset(buf2, 0, len2); free(buf2); }
    if (oe2) sync_entries_free(oe2, ne2);
    if (ot2) sync_tombstones_free(ot2, nt2);
    memset(buf, 0, len); free(buf);
    sync_entries_free(out_e, ne);
    sync_tombstones_free(out_t, nt);
    sync_entries_wipe(entries, 2);   /* stack arrays: wipe only, no free() */
    sync_tombstones_wipe(tombs, 1);
}

/* ---------- merge ---------- */

static sync_entry_t mk_entry(const char *svc, const char *user, const char *pass, int64_t at) {
    sync_entry_t e;
    sync_entry_init(&e);
    e.service = strdup(svc);
    e.username = strdup(user);
    e.password = strdup(pass);
    e.totp_secret = strdup("");
    e.recovery_codes = strdup("");
    e.updated_at = at;
    return e;
}

static void test_merge_cases(void **state) {
    (void)state;
    /* local: A(alice, t=100), B(bob, t=100)
     * remote: A(alice, t=200 newer), C(carol, new), plus tombstone for B. */
    sync_entry_t local[2], remote[2];
    local[0] = mk_entry("A", "alice", "old", 100);
    local[1] = mk_entry("B", "bob", "keep-or-delete", 100);
    remote[0] = mk_entry("A", "alice", "new", 200);
    remote[1] = mk_entry("C", "carol", "brand-new", 300);

    sync_tombstone_t rt[1];
    rt[0].service = strdup("B");
    rt[0].username = strdup("bob");
    rt[0].deleted_at = 500;

    sync_merge_report_t rep;
    assert_int_equal(sync_merge_vaults(local, 2, remote, 2, NULL, 0, rt, 1, &rep), 0);

    assert_int_equal(rep.added, 1);      /* C is new locally */
    assert_int_equal(rep.updated, 1);    /* A updated from remote (newer) */
    assert_int_equal(rep.identical, 0);
    assert_int_equal(rep.deleted, 1);    /* B deleted remotely after local edit */
    assert_int_equal(rep.conflicts, 1);  /* A differed on both sides */

    /* Verify winner selection. */
    const sync_merge_result_t *a_res = NULL, *c_res = NULL, *b_res = NULL;
    for (int i = 0; i < rep.result_count; i++) {
        if (strcmp(rep.results[i].service, "A") == 0) a_res = &rep.results[i];
        if (strcmp(rep.results[i].service, "C") == 0) c_res = &rep.results[i];
        if (strcmp(rep.results[i].service, "B") == 0) b_res = &rep.results[i];
    }
    assert_non_null(a_res);
    assert_int_equal(a_res->action, SYNC_MERGE_APPLY_REMOTE);
    assert_true(a_res->is_conflict);
    assert_string_equal(a_res->winner.password, "new");
    assert_int_equal(a_res->winner.updated_at, 200);

    assert_non_null(c_res);
    assert_int_equal(c_res->action, SYNC_MERGE_APPLY_REMOTE);
    assert_int_equal(c_res->winner.updated_at, 300);

    assert_non_null(b_res);
    assert_int_equal(b_res->action, SYNC_MERGE_DELETED);
    assert_int_equal(b_res->tombstone_at, 500);

    sync_merge_report_free(&rep);
    sync_entries_wipe(local, 2);
    sync_entries_wipe(remote, 2);
    sync_tombstones_wipe(rt, 1);
}

static void test_merge_deterministic_symmetry(void **state) {
    (void)state;
    /* Same updated_at on both sides, different content: both sides must
     * pick the same winner regardless of which snapshot is "local". */
    sync_entry_t a[1], b[1];
    a[0] = mk_entry("S", "user", "alpha", 500);
    b[0] = mk_entry("S", "user", "beta", 500);

    sync_merge_report_t r1, r2;
    assert_int_equal(sync_merge_vaults(a, 1, b, 1, NULL, 0, NULL, 0, &r1), 0);
    assert_int_equal(sync_merge_vaults(b, 1, a, 1, NULL, 0, NULL, 0, &r2), 0);

    assert_int_equal(r1.result_count, 1);
    assert_int_equal(r2.result_count, 1);
    /* Whichever direction, the winner must be the identical content. */
    assert_string_equal(r1.results[0].winner.password, r2.results[0].winner.password);

    sync_merge_report_free(&r1);
    sync_merge_report_free(&r2);
    sync_entries_wipe(a, 1);
    sync_entries_wipe(b, 1);
}

static void test_merge_tombstone_beats_older_entry(void **state) {
    (void)state;
    /* Remote has an entry the local side deleted AFTER the entry's timestamp:
     * the deletion must win and the entry must be reported as IGNORED. */
    sync_entry_t remote[1];
    remote[0] = mk_entry("X", "y", "resurrect-attempt", 100);

    sync_tombstone_t lt[1];
    lt[0].service = strdup("X");
    lt[0].username = strdup("y");
    lt[0].deleted_at = 900;

    sync_merge_report_t rep;
    assert_int_equal(sync_merge_vaults(NULL, 0, remote, 1, lt, 1, NULL, 0, &rep), 0);
    assert_int_equal(rep.added, 0);
    assert_int_equal(rep.result_count, 1);
    assert_int_equal(rep.results[0].action, SYNC_MERGE_IGNORED);

    sync_merge_report_free(&rep);
    sync_entries_wipe(remote, 1);
    sync_tombstones_wipe(lt, 1);
}

static void test_merge_identical_entries(void **state) {
    (void)state;
    sync_entry_t a[1], b[1];
    a[0] = mk_entry("Same", "user", "pass", 123);
    b[0] = mk_entry("same", "USER", "pass", 123); /* identity is case-insensitive */

    sync_merge_report_t rep;
    assert_int_equal(sync_merge_vaults(a, 1, b, 1, NULL, 0, NULL, 0, &rep), 0);
    assert_int_equal(rep.identical, 1);
    assert_int_equal(rep.result_count, 1);
    assert_int_equal(rep.results[0].action, SYNC_MERGE_IDENTICAL);

    sync_merge_report_free(&rep);
    sync_entries_wipe(a, 1);
    sync_entries_wipe(b, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ct_equal),
        cmocka_unit_test(test_handshake_roundtrip),
        cmocka_unit_test(test_handshake_wrong_psk_fails_confirmation),
        cmocka_unit_test(test_frame_roundtrip_and_direction),
        cmocka_unit_test(test_frame_replay_rejected),
        cmocka_unit_test(test_snapshot_roundtrip),
        cmocka_unit_test(test_merge_cases),
        cmocka_unit_test(test_merge_deterministic_symmetry),
        cmocka_unit_test(test_merge_tombstone_beats_older_entry),
        cmocka_unit_test(test_merge_identical_entries),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
