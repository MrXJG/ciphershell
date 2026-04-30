#include "core/audit_logger.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTextStream>

namespace gmssh {

AuditLogger::AuditLogger(QString log_file_path)
    : log_file_path_(std::move(log_file_path)) {
  const QFileInfo info(log_file_path_);
  QDir().mkpath(info.absolutePath());
}

void AuditLogger::logEvent(const QString& event_name, const QJsonObject& details) {
  QFile file(log_file_path_);
  if (!file.open(QIODevice::Append | QIODevice::Text)) {
    return;
  }

  QJsonObject entry = details;
  entry.insert(QStringLiteral("ts"),
               QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
  entry.insert(QStringLiteral("event"), event_name);

  file.write(QJsonDocument(entry).toJson(QJsonDocument::Compact));
  file.write("\n");
}

QStringList AuditLogger::readLastLines(int line_count) const {
  QStringList lines;

  QFile file(log_file_path_);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    return lines;
  }

  QTextStream stream(&file);
  while (!stream.atEnd()) {
    lines.push_back(stream.readLine());
  }

  if (line_count <= 0 || lines.size() <= line_count) {
    return lines;
  }

  return lines.mid(lines.size() - line_count);
}

const QString& AuditLogger::logFilePath() const {
  return log_file_path_;
}

}  // namespace gmssh
