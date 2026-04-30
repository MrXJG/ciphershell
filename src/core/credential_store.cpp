#include "core/credential_store.h"

#include "core/crypto_utils.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

namespace gmssh {
namespace {

QJsonObject loadStore(const QString& file_path, QString* error) {
  QFile file(file_path);
  if (!file.exists()) {
    return {};
  }

  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to open credential store");
    }
    return {};
  }

  const auto document = QJsonDocument::fromJson(file.readAll());
  if (!document.isObject()) {
    if (error != nullptr) {
      *error = QStringLiteral("credential store is corrupted");
    }
    return {};
  }

  return document.object();
}

bool saveStore(const QString& file_path, const QJsonObject& root, QString* error) {
  const QFileInfo info(file_path);
  QDir().mkpath(info.absolutePath());

  QSaveFile file(file_path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to write credential store");
    }
    return false;
  }

  file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
  if (!file.commit()) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to commit credential store");
    }
    return false;
  }

  return true;
}

}  // namespace

CredentialStore::CredentialStore(QString file_path) : file_path_(std::move(file_path)) {}

CredentialStore::Result CredentialStore::savePassword(
    const QString& profile_name,
    const QString& password) const {
  Result result;

  if (profile_name.trimmed().isEmpty()) {
    result.error = QStringLiteral("profile name is empty");
    return result;
  }

  const auto encrypted = encryptSecret(password.toUtf8());
  if (!encrypted.has_value()) {
    result.error = QStringLiteral("failed to encrypt credential");
    return result;
  }

  QString load_error;
  auto root = loadStore(file_path_, &load_error);
  if (!load_error.isEmpty()) {
    result.error = load_error;
    return result;
  }

  QJsonObject entry;
  entry.insert(
      QStringLiteral("salt"),
      QString::fromLatin1(encrypted->salt.toBase64()));
  entry.insert(
      QStringLiteral("iv"),
      QString::fromLatin1(encrypted->iv.toBase64()));
  entry.insert(
      QStringLiteral("tag"),
      QString::fromLatin1(encrypted->tag.toBase64()));
  entry.insert(
      QStringLiteral("cipher"),
      QString::fromLatin1(encrypted->cipher_text.toBase64()));

  root.insert(profile_name, entry);

  QString save_error;
  if (!saveStore(file_path_, root, &save_error)) {
    result.error = save_error;
    return result;
  }

  result.ok = true;
  return result;
}

CredentialStore::Result CredentialStore::loadPassword(
    const QString& profile_name) const {
  Result result;

  QString load_error;
  const auto root = loadStore(file_path_, &load_error);
  if (!load_error.isEmpty()) {
    result.error = load_error;
    return result;
  }

  if (!root.contains(profile_name)) {
    result.error = QStringLiteral("credential not found");
    return result;
  }

  const auto entry = root.value(profile_name).toObject();
  EncryptedBlob blob;
  blob.salt = QByteArray::fromBase64(entry.value(QStringLiteral("salt")).toString().toLatin1());
  blob.iv = QByteArray::fromBase64(entry.value(QStringLiteral("iv")).toString().toLatin1());
  blob.tag = QByteArray::fromBase64(entry.value(QStringLiteral("tag")).toString().toLatin1());
  blob.cipher_text =
      QByteArray::fromBase64(entry.value(QStringLiteral("cipher")).toString().toLatin1());

  const auto plain = decryptSecret(blob);
  if (!plain.has_value()) {
    result.error = QStringLiteral("failed to decrypt credential");
    return result;
  }

  result.ok = true;
  result.value = QString::fromUtf8(plain.value());
  return result;
}

CredentialStore::Result CredentialStore::removePassword(
    const QString& profile_name) const {
  Result result;

  QString load_error;
  auto root = loadStore(file_path_, &load_error);
  if (!load_error.isEmpty()) {
    result.error = load_error;
    return result;
  }

  root.remove(profile_name);

  QString save_error;
  if (!saveStore(file_path_, root, &save_error)) {
    result.error = save_error;
    return result;
  }

  result.ok = true;
  return result;
}

}  // namespace gmssh
