#pragma once

#include "core/audit_logger.h"
#include "core/credential_store.h"
#include "core/profile_repository.h"
#include "core/ssh_engine_adapter.h"
#include "gui/audit_log_view.h"
#include "gui/sftp_panel.h"

#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QPushButton>
#include <QSplitter>
#include <QTabWidget>
#include <QVector>
#include <optional>

class QAction;
class QCloseEvent;

namespace gmssh {

class TerminalSessionWidget;

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  MainWindow();

 protected:
  void closeEvent(QCloseEvent* event) override;

 private:
  void reloadProfiles();
  void onProfileSelected(int row);
  void onDeleteProfile();
  void onNewProfile();
  void onEditProfile();
  void onConnect();
  void onOpenSftpTool();
  void onOpenAuditLog();
  void applyGmHostSignaturePolicy(bool compatibility_bypass);

  void applyProfileFilter(const QString& keyword);
  void updateConnectionStatus(const QString& text);
  void applyVisualStyle();
  void restoreUiState();
  void persistUiState() const;

  bool editProfile(int row, bool creating_new);
  std::optional<ConnectionProfile> selectedProfile() const;
  std::optional<SessionSecrets> collectSecretsForConnect(ConnectionProfile& profile);
  bool validateProfile(const ConnectionProfile& profile, QString* error = nullptr) const;
  int findProfileByName(const QString& name) const;
  void ensureToolWindows();
  void closeTerminalTab(int idx);
  void installTerminalTabCloseButton(int idx, QWidget* tab_widget);
  void updateActiveTerminalStatus();
  TerminalSessionWidget* currentTerminalSession() const;
  bool syncSftpPanelToCurrentTerminal();

  QVector<ConnectionProfile> profiles_;

  ProfileRepository profile_repository_;
  CredentialStore credential_store_;
  AuditLogger audit_logger_;
  SshEngineAdapter ssh_adapter_;

  QSplitter* main_splitter_ = nullptr;

  QListWidget* profile_list_ = nullptr;
  QLineEdit* search_edit_ = nullptr;

  QTabWidget* terminal_tabs_ = nullptr;
  SftpPanel* sftp_panel_ = nullptr;
  AuditLogView* audit_view_ = nullptr;
  QDialog* sftp_window_ = nullptr;
  QDialog* audit_window_ = nullptr;

  QLabel* connection_status_label_ = nullptr;

  QPushButton* connect_button_ = nullptr;
  QPushButton* edit_button_ = nullptr;
  QPushButton* new_button_ = nullptr;
  QPushButton* delete_button_ = nullptr;
  QAction* edit_action_ = nullptr;
  QAction* open_sftp_action_ = nullptr;
  QAction* open_audit_action_ = nullptr;
  QAction* strict_hostsig_action_ = nullptr;
  QAction* compat_hostsig_action_ = nullptr;
};

}  // namespace gmssh
