#include "mqttsn/protection_openssl.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
  const std::array<std::uint8_t, 16> key{};
  mqttsn::OpenSslProtectionProvider provider(
      [&key](const mqttsn::ProtectionContext&) {
        return std::vector<std::uint8_t>(key.begin(), key.end());
      });

  const std::array<std::uint8_t, 16> prefix{
      0x12,0x00,0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,
      0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
  const std::array<std::uint8_t, 4> plaintext{
      0x04,0x0C,0x12,0x34};

  const mqttsn::ProtectionContext context{
      0x46u,
      0x01u,
      {},
      {},
      {},
      {},
      prefix};

  const auto protectedContent = provider.protect(context, plaintext);
  const std::array<std::uint8_t, 4> expectedCipher{
      0x27,0x43,0x12,0x9D};
  const std::array<std::uint8_t, 16> expectedTag{
      0xDF,0xFA,0x81,0x9C,0x4F,0xE6,0xD4,0x1C,
      0x49,0x12,0xA8,0x91,0xE4,0xC8,0x27,0x86};

  assert(std::equal(
      protectedContent.protectedPacket.begin(),
      protectedContent.protectedPacket.end(),
      expectedCipher.begin()));
  assert(std::equal(
      protectedContent.authenticationTag.begin(),
      protectedContent.authenticationTag.end(),
      expectedTag.begin()));

  const auto plain = provider.unprotect(
      context,
      protectedContent.protectedPacket,
      protectedContent.authenticationTag);
  assert(plain.size() == plaintext.size());
  assert(std::equal(plain.begin(), plain.end(), plaintext.begin()));

  return 0;
}
