// Copyright 2025 The BoringSSL Authors
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Tests for SSL_set1_client_key_shares, ported from BoringSSL's ssl_test.cc
// (commit dcaedb5676a70ed5dd5f6b365bf3dbef4bf79d88). |KeySharesInHandshake|
// covers the cases of the upstream runner tests, by the same names.

#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/ssl.h>

#include "../crypto/internal.h"
#include "internal.h"
#include "ssl_common_test.h"

BSSL_NAMESPACE_BEGIN

namespace {

static std::vector<uint16_t> Selections(const SSL *ssl) {
  return std::vector<uint16_t>(ssl->config->client_key_share_selections.begin(),
                               ssl->config->client_key_share_selections.end());
}

TEST(ClientKeySharesTest, SetClientKeyShares) {
  const struct {
    const char *description;
    std::vector<uint16_t> supported_groups;
    std::vector<uint16_t> key_shares;
    bool expected_success;
  } kTests[] = {
      {
          "Empty key shares with default supported groups",
          {},
          {},
          true,
      },
      {
          "Empty key shares with custom supported groups",
          {SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768},
          {},
          true,
      },
      {
          "One key share matching default supported groups",
          {},
          {SSL_GROUP_X25519},
          true,
      },
      {
          "One key share matching custom supported groups",
          {SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768},
          {SSL_GROUP_X25519},
          true,
      },
      {
          "Key share not in supported default groups",
          {},
          {SSL_GROUP_MLKEM1024},
          false,
      },
      {
          "Key share not in supported custom groups",
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1},
          {SSL_GROUP_X25519_MLKEM768},
          false,
      },
      {
          "Multiple key shares, in correct order",
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          {SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768},
          true,
      },
      {
          "Multiple key shares, out of order",
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519},
          false,
      },
      {
          "More than two key shares",
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768,
           SSL_GROUP_MLKEM1024},
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          true,
      },
      {
          "Key shares cover all supported groups",
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          true,
      },
      {
          "Multiple key shares, not all valid",
          {SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768},
          {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_X25519_MLKEM768},
          false,
      },
      {
          "Key shares contain duplicates",
          {},
          {SSL_GROUP_X25519, SSL_GROUP_X25519},
          false,
      },
      {
          // AWS-LC implements more groups than BoringSSL, so the selections
          // must hold every one of them.
          "Key shares for every implemented group",
          {SSL_GROUP_SECP224R1, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1,
           SSL_GROUP_SECP521R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1_MLKEM768,
           SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP384R1_MLKEM1024,
           SSL_GROUP_MLKEM512, SSL_GROUP_MLKEM768, SSL_GROUP_MLKEM1024},
          {SSL_GROUP_SECP224R1, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1,
           SSL_GROUP_SECP521R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1_MLKEM768,
           SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP384R1_MLKEM1024,
           SSL_GROUP_MLKEM512, SSL_GROUP_MLKEM768, SSL_GROUP_MLKEM1024},
          true,
      },
  };

  for (const auto &t : kTests) {
    SCOPED_TRACE(t.description);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);
    ASSERT_FALSE(ssl->config->has_client_key_share_selections);

    ASSERT_TRUE(SSL_set1_group_ids(ssl.get(), t.supported_groups.data(),
                                   t.supported_groups.size()));
    EXPECT_EQ(SSL_set1_client_key_shares(ssl.get(), t.key_shares.data(),
                                         t.key_shares.size()),
              t.expected_success);
    if (t.expected_success) {
      ASSERT_TRUE(ssl->config->has_client_key_share_selections);
      EXPECT_EQ(Selections(ssl.get()), t.key_shares);
    }
  }
}

// Test the behavior that modifying the SSL's supported groups results in
// clearing the previously set client key shares, iff the supported groups
// become incompatible with the key shares.
TEST(ClientKeySharesTest, ClientKeySharesResetAfterChangingGroups) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  ASSERT_FALSE(ssl->config->has_client_key_share_selections);

  // An initial groups list and key shares that are compatible.
  const uint16_t kGroups1[] = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519};
  const uint16_t kKeyShares[] = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519};
  ASSERT_TRUE(
      SSL_set1_group_ids(ssl.get(), kGroups1, OPENSSL_ARRAY_SIZE(kGroups1)));
  ASSERT_TRUE(SSL_set1_client_key_shares(ssl.get(), kKeyShares,
                                         OPENSSL_ARRAY_SIZE(kKeyShares)));
  ASSERT_TRUE(ssl->config->has_client_key_share_selections);
  EXPECT_EQ(ssl->config->client_key_share_selections.size(), 2u);

  // A new groups list that is still compatible with the previously set key
  // shares.
  const uint16_t kGroups2[] = {SSL_GROUP_MLKEM1024, SSL_GROUP_X25519_MLKEM768,
                               SSL_GROUP_X25519};
  ASSERT_TRUE(
      SSL_set1_group_ids(ssl.get(), kGroups2, OPENSSL_ARRAY_SIZE(kGroups2)));
  ASSERT_TRUE(ssl->config->has_client_key_share_selections);
  EXPECT_EQ(ssl->config->client_key_share_selections.size(), 2u);

  // A new groups list that is no longer compatible with the previously set key
  // shares. The other two setters must reset them too.
  const uint16_t kGroups3[] = {SSL_GROUP_MLKEM1024, SSL_GROUP_X25519};
  ASSERT_TRUE(
      SSL_set1_group_ids(ssl.get(), kGroups3, OPENSSL_ARRAY_SIZE(kGroups3)));
  EXPECT_FALSE(ssl->config->has_client_key_share_selections);

  ASSERT_TRUE(
      SSL_set1_group_ids(ssl.get(), kGroups1, OPENSSL_ARRAY_SIZE(kGroups1)));
  ASSERT_TRUE(SSL_set1_client_key_shares(ssl.get(), kKeyShares,
                                         OPENSSL_ARRAY_SIZE(kKeyShares)));
  ASSERT_TRUE(SSL_set1_groups_list(ssl.get(), "X25519"));
  EXPECT_FALSE(ssl->config->has_client_key_share_selections);

  ASSERT_TRUE(
      SSL_set1_group_ids(ssl.get(), kGroups1, OPENSSL_ARRAY_SIZE(kGroups1)));
  ASSERT_TRUE(SSL_set1_client_key_shares(ssl.get(), kKeyShares,
                                         OPENSSL_ARRAY_SIZE(kKeyShares)));
  const int kNids[] = {NID_X25519};
  ASSERT_TRUE(SSL_set1_groups(ssl.get(), kNids, OPENSSL_ARRAY_SIZE(kNids)));
  EXPECT_FALSE(ssl->config->has_client_key_share_selections);
}

// The groups the server saw in the client's first key_share extension.
static std::vector<uint16_t> g_first_key_share_groups;
static bool g_saw_client_hello = false;

static ssl_select_cert_result_t RecordKeyShareGroups(
    const SSL_CLIENT_HELLO *client_hello) {
  if (g_saw_client_hello) {
    return ssl_select_cert_success;
  }
  g_saw_client_hello = true;
  g_first_key_share_groups.clear();
  const uint8_t *data;
  size_t len;
  if (!SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_key_share,
                                            &data, &len)) {
    ADD_FAILURE() << "ClientHello had no key_share extension";
    return ssl_select_cert_error;
  }
  CBS cbs, list;
  CBS_init(&cbs, data, len);
  if (!CBS_get_u16_length_prefixed(&cbs, &list) || CBS_len(&cbs) != 0) {
    ADD_FAILURE() << "Malformed key_share";
    return ssl_select_cert_error;
  }
  while (CBS_len(&list) > 0) {
    uint16_t group;
    CBS key_exchange;
    if (!CBS_get_u16(&list, &group) ||
        !CBS_get_u16_length_prefixed(&list, &key_exchange)) {
      ADD_FAILURE() << "Malformed KeyShareEntry";
      return ssl_select_cert_error;
    }
    g_first_key_share_groups.push_back(group);
  }
  return ssl_select_cert_success;
}

struct HandshakeResult {
  std::vector<uint16_t> first_key_shares;
  bool hrr = false;
  uint16_t group = 0;
};

// Handshake runs a TLS 1.3 handshake. If |client_groups| is empty, the client
// uses its default groups. If |key_shares| is null, it uses its default key
// shares.
static bool Handshake(HandshakeResult *out,
                      const std::vector<uint16_t> &client_groups,
                      const std::vector<uint16_t> *key_shares,
                      const std::vector<uint16_t> &server_groups) {
  UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  if (!client_ctx || !server_ctx ||
      !SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION) ||
      !SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION) ||
      !SSL_CTX_set1_group_ids(server_ctx.get(), server_groups.data(),
                              server_groups.size())) {
    return false;
  }
  SSL_CTX_set_select_certificate_cb(server_ctx.get(), RecordKeyShareGroups);
  UniquePtr<SSL> client, server;
  if (!CreateClientAndServer(&client, &server, client_ctx.get(),
                             server_ctx.get()) ||
      (!client_groups.empty() &&
       !SSL_set1_group_ids(client.get(), client_groups.data(),
                           client_groups.size())) ||
      (key_shares != nullptr &&
       !SSL_set1_client_key_shares(client.get(), key_shares->data(),
                                   key_shares->size()))) {
    return false;
  }
  g_saw_client_hello = false;
  if (!CompleteHandshakes(client.get(), server.get())) {
    return false;
  }
  out->first_key_shares = g_first_key_share_groups;
  out->hrr = SSL_used_hello_retry_request(client.get());
  out->group = SSL_get_group_id(client.get());
  return true;
}

// The configured key shares are sent exactly, in order, and the handshake
// takes a HelloRetryRequest only when the server's group isn't among them.
// The server in each case supports only the group it should pick, so the
// result doesn't depend on whose preference order the server follows.
TEST(ClientKeySharesTest, KeySharesInHandshake) {
  struct Case {
    const char *name;
    std::vector<uint16_t> client_groups;  // empty for the default groups
    std::vector<uint16_t> key_shares;
    std::vector<uint16_t> server_groups;
    uint16_t expected_group;
    bool expected_hrr;
  };
  const std::vector<uint16_t> kThreeGroups = {
      SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP256R1};
  const std::vector<uint16_t> kAllGroups = {
      SSL_GROUP_SECP224R1,       SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,       SSL_GROUP_SECP521R1,
      SSL_GROUP_X25519,          SSL_GROUP_SECP256R1_MLKEM768,
      SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP384R1_MLKEM1024,
      SSL_GROUP_MLKEM512,        SSL_GROUP_MLKEM768,
      SSL_GROUP_MLKEM1024};
  const Case kCases[] = {
      {"CustomKeyShares",
       {SSL_GROUP_X25519, SSL_GROUP_SECP256R1},
       {SSL_GROUP_SECP256R1},
       {SSL_GROUP_SECP256R1},
       SSL_GROUP_SECP256R1,
       false},
      // Key shares configured without configuring the supported groups.
      {"CustomKeyShares-DefaultSupportedGroups",
       {},
       {SSL_GROUP_X25519},
       {SSL_GROUP_X25519},
       SSL_GROUP_X25519,
       false},
      // The top two of three supported groups.
      {"CustomKeyShares-Multiple",
       kThreeGroups,
       {SSL_GROUP_X25519, SSL_GROUP_X25519_MLKEM768},
       {SSL_GROUP_X25519},
       SSL_GROUP_X25519,
       false},
      // The first and last of three supported groups.
      {"CustomKeyShares-MultipleNonContiguous",
       kThreeGroups,
       {SSL_GROUP_X25519, SSL_GROUP_SECP256R1},
       {SSL_GROUP_X25519},
       SSL_GROUP_X25519,
       false},
      // Shares that don't include the group the server picks.
      {"CustomKeyShares-NotMostPreferred-HRR",
       kThreeGroups,
       {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP256R1},
       {SSL_GROUP_X25519},
       SSL_GROUP_X25519,
       true},
      // The server picks a share other than the first.
      {"CustomKeyShares-PeerSelectedLaterKeyShare",
       kThreeGroups,
       {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP256R1},
       {SSL_GROUP_SECP256R1},
       SSL_GROUP_SECP256R1,
       false},
      // A share for every group AWS-LC implements.
      {"CustomKeyShares-All",
       kAllGroups,
       kAllGroups,
       {SSL_GROUP_X25519},
       SSL_GROUP_X25519,
       false},
      // An empty key_share always costs a HelloRetryRequest.
      {"CustomKeyShares-Empty-HRR",
       {SSL_GROUP_X25519, SSL_GROUP_SECP256R1},
       {},
       {SSL_GROUP_SECP256R1},
       SSL_GROUP_SECP256R1,
       true},
  };
  for (const Case &c : kCases) {
    SCOPED_TRACE(c.name);
    HandshakeResult r;
    ASSERT_TRUE(Handshake(&r, c.client_groups, &c.key_shares, c.server_groups));
    EXPECT_EQ(r.first_key_shares, c.key_shares);
    EXPECT_EQ(r.hrr, c.expected_hrr);
    EXPECT_EQ(r.group, c.expected_group);
  }
}

// Without configured key shares, the default selection is unchanged: the first
// group and the first group of the other family.
TEST(ClientKeySharesTest, DefaultKeySharesUnchanged) {
  HandshakeResult r;
  ASSERT_TRUE(Handshake(
      &r, {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519, SSL_GROUP_SECP256R1},
      nullptr, {SSL_GROUP_X25519}));
  EXPECT_EQ(
      r.first_key_shares,
      (std::vector<uint16_t>{SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519}));
  EXPECT_FALSE(r.hrr);
}

}  // namespace

BSSL_NAMESPACE_END
