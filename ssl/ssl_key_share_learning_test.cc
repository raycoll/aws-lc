// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Tests for TLS 1.3 client key share learning
// (|SSL_set_enable_key_share_learning|).

#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/hpke.h>
#include <openssl/ssl.h>

#include "../crypto/internal.h"
#include "internal.h"
#include "ssl_common_test.h"

BSSL_NAMESPACE_BEGIN

namespace {

// The client's supported groups, unless a test changes them. The default key
// shares are X25519MLKEM768 and X25519; P-256 and P-384 are listed without
// shares.
const std::vector<uint16_t> kClientGroups = {
    SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519, SSL_GROUP_SECP256R1,
    SSL_GROUP_SECP384R1};

const std::vector<uint16_t> kDefaultShares = {SSL_GROUP_X25519_MLKEM768,
                                              SSL_GROUP_X25519};
const std::vector<uint16_t> kP256Share = {SSL_GROUP_SECP256R1};
const std::vector<uint16_t> kP384Share = {SSL_GROUP_SECP384R1};

// What the server saw in a ClientHello.
struct ClientHelloGroups {
  std::vector<uint16_t> supported_groups;
  std::vector<uint16_t> key_shares;
};

std::vector<ClientHelloGroups> g_client_hellos;

bool IsGrease(uint16_t value) { return (value & 0x0f0f) == 0x0a0a; }

bool ReadGroups(const SSL_CLIENT_HELLO *client_hello, ClientHelloGroups *out) {
  const uint8_t *data;
  size_t len;
  CBS cbs, list;
  if (!SSL_early_callback_ctx_extension_get(
          client_hello, TLSEXT_TYPE_supported_groups, &data, &len)) {
    return false;
  }
  CBS_init(&cbs, data, len);
  if (!CBS_get_u16_length_prefixed(&cbs, &list) || CBS_len(&cbs) != 0) {
    return false;
  }
  while (CBS_len(&list) > 0) {
    uint16_t group;
    if (!CBS_get_u16(&list, &group)) {
      return false;
    }
    if (!IsGrease(group)) {
      out->supported_groups.push_back(group);
    }
  }
  if (!SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_key_share,
                                            &data, &len)) {
    return false;
  }
  CBS_init(&cbs, data, len);
  if (!CBS_get_u16_length_prefixed(&cbs, &list) || CBS_len(&cbs) != 0) {
    return false;
  }
  while (CBS_len(&list) > 0) {
    uint16_t group;
    CBS key_exchange;
    if (!CBS_get_u16(&list, &group) ||
        !CBS_get_u16_length_prefixed(&list, &key_exchange)) {
      return false;
    }
    if (!IsGrease(group)) {
      out->key_shares.push_back(group);
    }
  }
  return true;
}

ssl_select_cert_result_t RecordClientHello(
    const SSL_CLIENT_HELLO *client_hello) {
  ClientHelloGroups groups;
  if (!ReadGroups(client_hello, &groups)) {
    ADD_FAILURE() << "Could not parse the ClientHello's groups";
    return ssl_select_cert_error;
  }
  g_client_hellos.push_back(groups);
  return ssl_select_cert_success;
}

// NewClientContext returns a client context with key share learning enabled.
UniquePtr<SSL_CTX> NewClientContext() {
  UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  if (!ctx || !SSL_CTX_set1_group_ids(ctx.get(), kClientGroups.data(),
                                      kClientGroups.size())) {
    return nullptr;
  }
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_CLIENT);
  SSL_CTX_set_enable_key_share_learning(ctx.get(), 1);
  return ctx;
}

// NewServerContext returns a TLS 1.3 server that supports only |groups|. Each
// test chooses them so that the server picks the same group whether it
// selects by its own order or the client's.
UniquePtr<SSL_CTX> NewServerContext(std::vector<uint16_t> groups) {
  UniquePtr<SSL_CTX> ctx = CreateContextWithTestCertificate(TLS_method());
  if (!ctx || !SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) ||
      !SSL_CTX_set1_group_ids(ctx.get(), groups.data(), groups.size())) {
    return nullptr;
  }
  SSL_CTX_set_select_certificate_cb(ctx.get(), RecordClientHello);
  return ctx;
}

// Options for one handshake.
struct ConnectOptions {
  // session, if not null, is given to the client with |SSL_set_session|.
  SSL_SESSION *session = nullptr;
  // client_groups, if not empty, replaces the client's supported groups for
  // this connection.
  std::vector<uint16_t> client_groups;
  // reject_server_certificate makes the handshake fail after the ServerHello.
  bool reject_server_certificate = false;
  // learning_disabled turns key share learning off for this connection.
  bool learning_disabled = false;
  // key_shares, if |has_key_shares| is set, is passed to
  // |SSL_set1_client_key_shares|.
  bool has_key_shares = false;
  std::vector<uint16_t> key_shares;
  // ech_config_list, if not empty, is passed to |SSL_set1_ech_config_list|.
  std::vector<uint8_t> ech_config_list;
};

// A Connection is the result of one handshake.
struct Connection {
  UniquePtr<SSL> client, server;
  // first_key_shares is the groups of the first ClientHello's key shares.
  std::vector<uint16_t> first_key_shares;
  bool hrr = false;
  bool reused = false;
  uint16_t group = 0;
  // ticket is the last session the client received from a NewSessionTicket,
  // or null if it received none.
  UniquePtr<SSL_SESSION> ticket;
  // session is the client's |SSL_get1_session| afterwards.
  UniquePtr<SSL_SESSION> session;
};

// Connect runs a handshake and reads any NewSessionTickets. It checks that
// every ClientHello the server saw listed the client's supported groups
// unchanged, since learning must never change them, including on handshakes
// that fail.
bool Connect(Connection *out, SSL_CTX *client_ctx, SSL_CTX *server_ctx,
             const ConnectOptions &opts = ConnectOptions()) {
  g_client_hellos.clear();
  g_last_session = nullptr;
  SSL_CTX_sess_set_new_cb(client_ctx, SaveLastSession);
  bool ok =
      CreateClientAndServer(&out->client, &out->server, client_ctx, server_ctx);
  SSL *client = out->client.get();
  if (ok && !opts.client_groups.empty()) {
    ok = SSL_set1_group_ids(client, opts.client_groups.data(),
                            opts.client_groups.size());
  }
  if (ok && opts.session != nullptr) {
    ok = SSL_set_session(client, opts.session);
  }
  if (ok && opts.reject_server_certificate) {
    SSL_set_custom_verify(client, SSL_VERIFY_PEER,
                          [](SSL *, uint8_t *) { return ssl_verify_invalid; });
  }
  if (ok && opts.learning_disabled) {
    SSL_set_enable_key_share_learning(client, 0);
  }
  if (ok && opts.has_key_shares) {
    ok = SSL_set1_client_key_shares(client, opts.key_shares.data(),
                                    opts.key_shares.size());
  }
  if (ok && !opts.ech_config_list.empty()) {
    ok = SSL_set1_ech_config_list(client, opts.ech_config_list.data(),
                                  opts.ech_config_list.size());
  }
  if (ok) {
    bool completed = CompleteHandshakes(client, out->server.get());
    ok = opts.reject_server_certificate
             ? !completed
             : completed && FlushNewSessionTickets(client, out->server.get());
  }
  SSL_CTX_sess_set_new_cb(client_ctx, nullptr);
  if (!ok || g_client_hellos.empty()) {
    return false;
  }
  const std::vector<uint16_t> &expected =
      opts.client_groups.empty() ? kClientGroups : opts.client_groups;
  for (const ClientHelloGroups &hello : g_client_hellos) {
    EXPECT_EQ(hello.supported_groups, expected);
  }
  out->first_key_shares = g_client_hellos[0].key_shares;
  out->hrr = SSL_used_hello_retry_request(client);
  out->reused = SSL_session_reused(client);
  out->group = SSL_get_group_id(client);
  out->ticket = std::move(g_last_session);
  out->session.reset(SSL_get1_session(client));
  return true;
}

// RoundTrip serializes and parses |session|.
UniquePtr<SSL_SESSION> RoundTrip(const SSL_SESSION *session,
                                 const SSL_CTX *ctx) {
  uint8_t *der = nullptr;
  size_t der_len;
  if (!SSL_SESSION_to_bytes(session, &der, &der_len)) {
    return nullptr;
  }
  UniquePtr<uint8_t> free_der(der);
  return UniquePtr<SSL_SESSION>(SSL_SESSION_from_bytes(der, der_len, ctx));
}

// A client pays a HelloRetryRequest the first time it meets a server that
// picks a group it didn't share, and none the next time, when it offers the
// session from that handshake. The session keeps the group when serialized.
TEST(KeyShareLearningTest, LearnedGroupAvoidsHelloRetryRequest) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  Connection cold;
  ASSERT_TRUE(Connect(&cold, client_ctx.get(), server_ctx.get()));
  EXPECT_EQ(cold.first_key_shares, kDefaultShares);
  EXPECT_TRUE(cold.hrr);
  EXPECT_EQ(cold.group, SSL_GROUP_SECP256R1);
  ASSERT_TRUE(cold.ticket);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(cold.ticket.get()),
            SSL_GROUP_SECP256R1);

  UniquePtr<SSL_SESSION> decoded =
      RoundTrip(cold.ticket.get(), client_ctx.get());
  ASSERT_TRUE(decoded);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(decoded.get()),
            SSL_GROUP_SECP256R1);

  for (SSL_SESSION *session : {cold.ticket.get(), decoded.get()}) {
    SCOPED_TRACE(session == decoded.get() ? "decoded" : "ticket");
    ConnectOptions opts;
    opts.session = session;
    Connection warm;
    ASSERT_TRUE(Connect(&warm, client_ctx.get(), server_ctx.get(), opts));
    EXPECT_EQ(warm.first_key_shares, kP256Share);
    EXPECT_FALSE(warm.hrr);
    EXPECT_TRUE(warm.reused);
    EXPECT_EQ(warm.group, SSL_GROUP_SECP256R1);
  }
}

// Without key share learning, a client records no group and predicts none,
// and resumption works as before. A client that has learning off ignores a
// group another client learned.
TEST(KeyShareLearningTest, DisabledByDefault) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  UniquePtr<SSL_CTX> default_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(default_ctx);
  ASSERT_TRUE(SSL_CTX_set1_group_ids(default_ctx.get(), kClientGroups.data(),
                                     kClientGroups.size()));
  SSL_CTX_set_session_cache_mode(default_ctx.get(), SSL_SESS_CACHE_CLIENT);
  Connection off;
  ASSERT_TRUE(Connect(&off, default_ctx.get(), server_ctx.get()));
  ASSERT_TRUE(off.ticket);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(off.ticket.get()), 0);
  ConnectOptions resume;
  resume.session = off.ticket.get();
  Connection off_again;
  ASSERT_TRUE(Connect(&off_again, default_ctx.get(), server_ctx.get(), resume));
  EXPECT_EQ(off_again.first_key_shares, kDefaultShares);
  EXPECT_TRUE(off_again.hrr);
  EXPECT_TRUE(off_again.reused);

  Connection learned;
  ASSERT_TRUE(Connect(&learned, client_ctx.get(), server_ctx.get()));
  ASSERT_TRUE(learned.ticket);
  ConnectOptions turned_off;
  turned_off.session = learned.ticket.get();
  turned_off.learning_disabled = true;
  Connection ignored;
  ASSERT_TRUE(
      Connect(&ignored, client_ctx.get(), server_ctx.get(), turned_off));
  EXPECT_EQ(ignored.first_key_shares, kDefaultShares);
  EXPECT_TRUE(ignored.hrr);
}

// A server that issues no tickets still teaches the client its group. The
// session from |SSL_get1_session| is not resumable but carries the group, and
// offering it changes the key share, not resumption.
TEST(KeyShareLearningTest, ServerWithoutTicketsTeachesGroup) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  SSL_CTX_set_options(server_ctx.get(), SSL_OP_NO_TICKET);

  Connection cold;
  ASSERT_TRUE(Connect(&cold, client_ctx.get(), server_ctx.get()));
  EXPECT_FALSE(cold.ticket);
  ASSERT_TRUE(cold.session);
  EXPECT_FALSE(SSL_SESSION_is_resumable(cold.session.get()));
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(cold.session.get()),
            SSL_GROUP_SECP256R1);

  UniquePtr<SSL_SESSION> decoded =
      RoundTrip(cold.session.get(), client_ctx.get());
  ASSERT_TRUE(decoded);
  for (SSL_SESSION *session : {cold.session.get(), decoded.get()}) {
    SCOPED_TRACE(session == decoded.get() ? "decoded" : "session");
    ConnectOptions opts;
    opts.session = session;
    Connection warm;
    ASSERT_TRUE(Connect(&warm, client_ctx.get(), server_ctx.get(), opts));
    EXPECT_EQ(warm.first_key_shares, kP256Share);
    EXPECT_FALSE(warm.hrr);
    EXPECT_FALSE(warm.reused);
    EXPECT_EQ(warm.group, SSL_GROUP_SECP256R1);
  }
}

// A learned group the client no longer supports is ignored, and the default
// key shares are sent.
TEST(KeyShareLearningTest, UnsupportedLearnedGroupIgnored) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  // P-256 by the client's order and by the server's.
  UniquePtr<SSL_CTX> server_ctx =
      NewServerContext({SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  Connection cold;
  ASSERT_TRUE(Connect(&cold, client_ctx.get(), server_ctx.get()));
  ASSERT_TRUE(cold.ticket);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(cold.ticket.get()),
            SSL_GROUP_SECP256R1);

  ConnectOptions opts;
  opts.session = cold.ticket.get();
  opts.client_groups = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519,
                        SSL_GROUP_SECP384R1};
  Connection warm;
  ASSERT_TRUE(Connect(&warm, client_ctx.get(), server_ctx.get(), opts));
  EXPECT_EQ(warm.first_key_shares, kDefaultShares);
  EXPECT_TRUE(warm.hrr);
  EXPECT_EQ(warm.group, SSL_GROUP_SECP384R1);
}

// A failed handshake teaches the client nothing. The session it leaves holds
// the group from a ServerHello whose server was never authenticated, but no
// learned group, and offering it leaves the default key shares.
TEST(KeyShareLearningTest, FailedHandshakeNoLearning) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ConnectOptions fail;
  fail.reject_server_certificate = true;
  Connection failed;
  ASSERT_TRUE(Connect(&failed, client_ctx.get(), server_ctx.get(), fail));
  EXPECT_TRUE(failed.hrr);
  ASSERT_TRUE(failed.session);
  EXPECT_EQ(failed.session->group_id, SSL_GROUP_SECP256R1);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(failed.session.get()), 0);

  ConnectOptions opts;
  opts.session = failed.session.get();
  Connection next;
  ASSERT_TRUE(Connect(&next, client_ctx.get(), server_ctx.get(), opts));
  EXPECT_EQ(next.first_key_shares, kDefaultShares);
  EXPECT_TRUE(next.hrr);
}

// An expired session predicts nothing, and the handshake that replaces it
// learns the group again.
TEST(KeyShareLearningTest, ExpiredSessionNoLearning) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  Connection cold;
  ASSERT_TRUE(Connect(&cold, client_ctx.get(), server_ctx.get()));
  ASSERT_TRUE(cold.ticket);
  ASSERT_TRUE(cold.session);

  for (SSL_SESSION *session : {cold.ticket.get(), cold.session.get()}) {
    SCOPED_TRACE(session == cold.ticket.get() ? "ticket" : "session");
    SSL_SESSION_set_time(session, 1);
    SSL_SESSION_set_timeout(session, 1);
    ConnectOptions opts;
    opts.session = session;
    Connection warm;
    ASSERT_TRUE(Connect(&warm, client_ctx.get(), server_ctx.get(), opts));
    EXPECT_EQ(warm.first_key_shares, kDefaultShares);
    EXPECT_TRUE(warm.hrr);
    ASSERT_TRUE(warm.ticket);
    EXPECT_EQ(SSL_SESSION_get_learned_group_id(warm.ticket.get()),
              SSL_GROUP_SECP256R1);
  }
}

// Resumption never changes the session the application offered, which may be
// shared with other connections. When a resumed handshake negotiates a new
// group, the sessions from it carry the new group instead.
TEST(KeyShareLearningTest, ResumptionLeavesOfferedSessionAlone) {
  UniquePtr<SSL_CTX> client_ctx = NewClientContext();
  UniquePtr<SSL_CTX> server_ctx = NewServerContext({SSL_GROUP_SECP256R1});
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  Connection cold;
  ASSERT_TRUE(Connect(&cold, client_ctx.get(), server_ctx.get()));
  ASSERT_TRUE(cold.ticket);

  // The same server, now supporting only P-384, still resumes the ticket.
  const uint16_t kP384 = SSL_GROUP_SECP384R1;
  ASSERT_TRUE(SSL_CTX_set1_group_ids(server_ctx.get(), &kP384, 1));
  ConnectOptions opts;
  opts.session = cold.ticket.get();
  Connection resumed;
  ASSERT_TRUE(Connect(&resumed, client_ctx.get(), server_ctx.get(), opts));
  EXPECT_TRUE(resumed.reused);
  EXPECT_EQ(resumed.first_key_shares, kP256Share);
  EXPECT_TRUE(resumed.hrr);
  EXPECT_EQ(resumed.group, SSL_GROUP_SECP384R1);
  EXPECT_EQ(cold.ticket->group_id, SSL_GROUP_SECP256R1);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(cold.ticket.get()),
            SSL_GROUP_SECP256R1);
  ASSERT_TRUE(resumed.ticket);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(resumed.ticket.get()),
            SSL_GROUP_SECP384R1);
  ASSERT_TRUE(resumed.session);
  EXPECT_EQ(SSL_SESSION_get_learned_group_id(resumed.session.get()),
            SSL_GROUP_SECP384R1);
}

}  // namespace

BSSL_NAMESPACE_END
