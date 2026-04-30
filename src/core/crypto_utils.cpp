#include "core/crypto_utils.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QRandomGenerator>
#include <QSysInfo>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace gmssh {
namespace {

constexpr int kPbkdf2Rounds = 150000;
constexpr int kKeyBytes = 32;
constexpr int kIvBytes = 12;
constexpr int kTagBytes = 16;
constexpr int kSaltBytes = 16;

bool deriveKey(
    const QByteArray& material,
    const QByteArray& salt,
    unsigned char* key,
    int key_len) {
  return PKCS5_PBKDF2_HMAC(
             material.constData(),
             material.size(),
             reinterpret_cast<const unsigned char*>(salt.constData()),
             salt.size(),
             kPbkdf2Rounds,
             EVP_sha256(),
             key_len,
             key) == 1;
}

}  // namespace

QByteArray machineKeyMaterial() {
  QByteArray material;
  material.append(QSysInfo::machineUniqueId());
  material.append(QSysInfo::machineHostName().toUtf8());
  material.append(qEnvironmentVariable("USER").toUtf8());
  material.append(qEnvironmentVariable("USERNAME").toUtf8());

  if (material.isEmpty()) {
    material = QByteArrayLiteral("gmssh-fallback-material");
  }

  return QCryptographicHash::hash(material, QCryptographicHash::Sha256);
}

std::optional<EncryptedBlob> encryptSecret(const QByteArray& plain_text) {
  EncryptedBlob blob;
  blob.salt.resize(kSaltBytes);
  blob.iv.resize(kIvBytes);

  if (RAND_bytes(reinterpret_cast<unsigned char*>(blob.salt.data()), kSaltBytes) != 1 ||
      RAND_bytes(reinterpret_cast<unsigned char*>(blob.iv.data()), kIvBytes) != 1) {
    return std::nullopt;
  }

  unsigned char key[kKeyBytes];
  if (!deriveKey(machineKeyMaterial(), blob.salt, key, kKeyBytes)) {
    return std::nullopt;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return std::nullopt;
  }

  int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvBytes, nullptr);
  ok &= EVP_EncryptInit_ex(
      ctx,
      nullptr,
      nullptr,
      key,
      reinterpret_cast<const unsigned char*>(blob.iv.constData()));

  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  blob.cipher_text.resize(plain_text.size());
  int out_len = 0;
  ok = EVP_EncryptUpdate(
      ctx,
      reinterpret_cast<unsigned char*>(blob.cipher_text.data()),
      &out_len,
      reinterpret_cast<const unsigned char*>(plain_text.constData()),
      plain_text.size());

  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  int final_len = 0;
  ok = EVP_EncryptFinal_ex(
      ctx,
      reinterpret_cast<unsigned char*>(blob.cipher_text.data()) + out_len,
      &final_len);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  blob.cipher_text.resize(out_len + final_len);
  blob.tag.resize(kTagBytes);
  ok = EVP_CIPHER_CTX_ctrl(
      ctx,
      EVP_CTRL_GCM_GET_TAG,
      kTagBytes,
      reinterpret_cast<unsigned char*>(blob.tag.data()));

  EVP_CIPHER_CTX_free(ctx);

  if (ok != 1) {
    return std::nullopt;
  }

  return blob;
}

std::optional<QByteArray> decryptSecret(const EncryptedBlob& blob) {
  if (blob.salt.size() != kSaltBytes || blob.iv.size() != kIvBytes ||
      blob.tag.size() != kTagBytes) {
    return std::nullopt;
  }

  unsigned char key[kKeyBytes];
  if (!deriveKey(machineKeyMaterial(), blob.salt, key, kKeyBytes)) {
    return std::nullopt;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return std::nullopt;
  }

  int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvBytes, nullptr);
  ok &= EVP_DecryptInit_ex(
      ctx,
      nullptr,
      nullptr,
      key,
      reinterpret_cast<const unsigned char*>(blob.iv.constData()));

  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  QByteArray plain_text;
  plain_text.resize(blob.cipher_text.size());

  int out_len = 0;
  ok = EVP_DecryptUpdate(
      ctx,
      reinterpret_cast<unsigned char*>(plain_text.data()),
      &out_len,
      reinterpret_cast<const unsigned char*>(blob.cipher_text.constData()),
      blob.cipher_text.size());

  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  ok = EVP_CIPHER_CTX_ctrl(
      ctx,
      EVP_CTRL_GCM_SET_TAG,
      kTagBytes,
      const_cast<char*>(blob.tag.constData()));

  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }

  int final_len = 0;
  ok = EVP_DecryptFinal_ex(
      ctx,
      reinterpret_cast<unsigned char*>(plain_text.data()) + out_len,
      &final_len);

  EVP_CIPHER_CTX_free(ctx);

  if (ok != 1) {
    return std::nullopt;
  }

  plain_text.resize(out_len + final_len);
  return plain_text;
}

}  // namespace gmssh
