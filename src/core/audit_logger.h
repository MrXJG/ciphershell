#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace gmssh {

class AuditLogger {
 public:
  explicit AuditLogger(QString log_file_path);

  void logEvent(const QString& event_name, const QJsonObject& details = {});
  QStringList readLastLines(int line_count) const;

  const QString& logFilePath() const;

 private:
  QString log_file_path_;
};

}  // namespace gmssh
