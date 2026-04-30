#pragma once

#include <QByteArray>
#include <optional>

namespace gmssh {

struct EncryptedBlob {
  QByteArray salt;
  QByteArray iv;
  QByteArray tag;
  QByteArray cipher_text;
};

QByteArray machineKeyMaterial();
std::optional<EncryptedBlob> encryptSecret(const QByteArray& plain_text);
std::optional<QByteArray> decryptSecret(const EncryptedBlob& blob);

}  // namespace gmssh
