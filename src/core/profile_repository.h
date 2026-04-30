#pragma once

#include "core/types.h"

#include <QString>
#include <QVector>

namespace gmssh {

class ProfileRepository {
 public:
  explicit ProfileRepository(QString profile_file_path);

  QVector<ConnectionProfile> loadAll(QString* error = nullptr) const;
  bool saveAll(const QVector<ConnectionProfile>& profiles, QString* error = nullptr) const;

 private:
  QString profile_file_path_;
};

}  // namespace gmssh
