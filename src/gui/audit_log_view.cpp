#include "gui/audit_log_view.h"

#include <QFile>
#include <QHBoxLayout>
#include <QVBoxLayout>

namespace gmssh {

AuditLogView::AuditLogView(QWidget* parent) : QWidget(parent) {
  auto* layout = new QVBoxLayout(this);
  auto* top_row = new QHBoxLayout();
  refresh_button_ = new QPushButton(QStringLiteral("刷新"), this);
  top_row->addWidget(refresh_button_);
  top_row->addStretch();

  path_label_ = new QLabel(this);
  path_label_->setObjectName(QStringLiteral("auditLogPathLabel"));
  path_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  path_label_->setWordWrap(true);

  text_ = new QPlainTextEdit(this);
  text_->setReadOnly(true);

  layout->addLayout(top_row);
  layout->addWidget(path_label_);
  layout->addWidget(text_);

  connect(refresh_button_, &QPushButton::clicked, this, &AuditLogView::refresh);
}

void AuditLogView::setLogFilePath(QString path) {
  log_file_path_ = std::move(path);
  path_label_->setText(QStringLiteral("日志文件：%1").arg(log_file_path_));
  path_label_->setToolTip(log_file_path_);
}

void AuditLogView::refresh() {
  QFile file(log_file_path_);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    text_->setPlainText(QStringLiteral("暂无审计日志。\n日志文件：%1").arg(log_file_path_));
    return;
  }

  text_->setPlainText(QString::fromUtf8(file.readAll()));
}

}  // namespace gmssh
