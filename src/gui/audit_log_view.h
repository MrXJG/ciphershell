#pragma once

#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QWidget>

namespace gmssh {

class AuditLogView : public QWidget {
  Q_OBJECT

 public:
  explicit AuditLogView(QWidget* parent = nullptr);

  void setLogFilePath(QString path);
  void refresh();

 private:
  QString log_file_path_;
  QLabel* path_label_;
  QPlainTextEdit* text_;
  QPushButton* refresh_button_;
};

}  // namespace gmssh
