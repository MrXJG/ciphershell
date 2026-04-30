#include "core/profile_repository.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>

namespace gmssh {

ProfileRepository::ProfileRepository(QString profile_file_path)
    : profile_file_path_(std::move(profile_file_path)) {}

QVector<ConnectionProfile> ProfileRepository::loadAll(QString* error) const {
  QVector<ConnectionProfile> profiles;

  QFile file(profile_file_path_);
  if (!file.exists()) {
    return profiles;
  }

  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to open profile file for reading");
    }
    return {};
  }

  const auto document = QJsonDocument::fromJson(file.readAll());
  if (!document.isArray()) {
    if (error != nullptr) {
      *error = QStringLiteral("profile file is not a JSON array");
    }
    return {};
  }

  for (const auto& value : document.array()) {
    QString parse_error;
    const auto profile = connectionProfileFromJson(value.toObject(), &parse_error);
    if (!profile.has_value()) {
      if (error != nullptr) {
        *error = QStringLiteral("invalid profile entry: %1").arg(parse_error);
      }
      return {};
    }
    profiles.push_back(profile.value());
  }

  return profiles;
}

bool ProfileRepository::saveAll(
    const QVector<ConnectionProfile>& profiles,
    QString* error) const {
  const QFileInfo info(profile_file_path_);
  QDir().mkpath(info.absolutePath());

  QJsonArray array;
  for (const auto& profile : profiles) {
    array.append(toJson(profile));
  }

  QSaveFile file(profile_file_path_);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to open profile file for writing");
    }
    return false;
  }

  file.write(QJsonDocument(array).toJson(QJsonDocument::Indented));
  if (!file.commit()) {
    if (error != nullptr) {
      *error = QStringLiteral("failed to commit profile file");
    }
    return false;
  }

  return true;
}

}  // namespace gmssh
