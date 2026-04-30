#pragma once

#include "core/audit_logger.h"
#include "core/ssh_engine_adapter.h"
#include "core/types.h"

#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QWidget>

class QShowEvent;
class QEvent;

namespace gmssh {

class SftpPanel : public QWidget {
  Q_OBJECT

 public:
  explicit SftpPanel(QWidget* parent = nullptr);

  void setEngineAdapter(const SshEngineAdapter* adapter);
  void setAuditLogger(AuditLogger* logger);
  void setContext(ConnectionProfile profile, SessionSecrets secrets);
  void clearContext();
  void refreshPendingInitial();

 protected:
  void showEvent(QShowEvent* event) override;
  bool eventFilter(QObject* watched, QEvent* event) override;

 private:
  SftpExecutionResult runBatch(
      const QStringList& commands,
      const QString& event_name,
      bool show_success_output = false);
  void refreshRemoteList();
  void refreshRemoteListFor(QString directory);
  void enterParentDirectory();
  void enterSelectedDirectory(QListWidgetItem* item);
  void syncSelectedRemote(QListWidgetItem* item);
  void chooseUploadFile();
  void chooseDownloadDirectory();
  void uploadToCurrentDirectory();
  void downloadSelectedRemote();
  void renameSelectedRemote();
  void createDirectory();
  void deleteSelectedFile();
  void deleteSelectedDirectory();
  void chmodSelectedRemote();
  void setControlsEnabled(bool enabled);
  void updateStatusLabel(const SftpExecutionResult* result = nullptr);
  void prependLogBlock(QString text);
  QString selectedRemotePath() const;
  QString currentRemoteDir() const;
  QString contextKey(const ConnectionProfile& profile) const;
  void setCurrentRemoteDir(QString directory);

  const SshEngineAdapter* adapter_ = nullptr;
  AuditLogger* audit_logger_ = nullptr;
  ConnectionProfile profile_;
  SessionSecrets secrets_;
  bool has_context_ = false;
  bool pending_initial_refresh_ = false;
  QString context_key_;
  QString current_remote_dir_;

  QLabel* status_label_;
  QLineEdit* remote_dir_edit_;
  QListWidget* remote_list_;
  QLineEdit* selected_remote_edit_;
  QLineEdit* upload_file_edit_;
  QLineEdit* download_dir_edit_;
  QPlainTextEdit* output_view_;

  QPushButton* refresh_button_;
  QPushButton* parent_button_;
  QPushButton* choose_upload_button_;
  QPushButton* upload_button_;
  QPushButton* choose_download_dir_button_;
  QPushButton* download_button_;
  QPushButton* rename_button_;
  QPushButton* mkdir_button_;
  QPushButton* delete_file_button_;
  QPushButton* delete_dir_button_;
  QPushButton* chmod_button_;
};

}  // namespace gmssh
