#pragma once

#include <QString>

namespace gmssh {

class CredentialStore {
 public:
  struct Result {
    bool ok = false;
    QString value;
    QString error;
  };

  explicit CredentialStore(QString file_path);

  Result savePassword(const QString& profile_name, const QString& password) const;
  Result loadPassword(const QString& profile_name) const;
  Result removePassword(const QString& profile_name) const;

 private:
  QString file_path_;
};

}  // namespace gmssh
