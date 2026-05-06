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
#include <QPoint>
#include <QSplitter>
#include <QStackedWidget>
#include <QTabWidget>
#include <QToolButton>
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
  void applyGmHostSignaturePolicy(GmHostSignaturePolicy policy);

  void applyProfileFilter(const QString& keyword);
  void updateConnectionStatus(const QString& text);
  void applyVisualStyle();
  void restoreUiState();
  void persistUiState() const;
  void refreshProfileCardStates();
  void refreshContextPanels();
  void showProfileContextMenu(const QPoint& pos);
  void showTerminalTabContextMenu(const QPoint& pos);
  void updatePaneLayoutForSessionState();
  TerminalSessionWidget* terminalSessionAtTab(int idx) const;
  bool startTerminalSession(ConnectionProfile profile, SessionSecrets secrets);
  void duplicateTerminalSession(int idx);
  void exportTerminalSessionContent(int idx);

  bool editProfile(int row, bool creating_new);
  std::optional<ConnectionProfile> selectedProfile() const;
  std::optional<SessionSecrets> collectSecretsForConnect(ConnectionProfile& profile);
  bool validateProfile(const ConnectionProfile& profile, QString* error = nullptr) const;
  int findProfileByName(const QString& name) const;
  void ensureToolWindows();
  void closeTerminalTab(int idx);
  void updateActiveTerminalStatus();
  TerminalSessionWidget* currentTerminalSession() const;
  bool syncSftpPanelToCurrentTerminal();

  QVector<ConnectionProfile> profiles_;

  ProfileRepository profile_repository_;
  CredentialStore credential_store_;
  AuditLogger audit_logger_;
  SshEngineAdapter ssh_adapter_;

  QSplitter* main_splitter_ = nullptr;
  QWidget* left_panel_ = nullptr;
  QStackedWidget* left_navigation_stack_ = nullptr;
  QToolButton* left_nav_expand_button_ = nullptr;
  QToolButton* left_nav_collapse_button_ = nullptr;

  QListWidget* profile_list_ = nullptr;
  QLineEdit* search_edit_ = nullptr;

  QTabWidget* terminal_tabs_ = nullptr;
  SftpPanel* sftp_panel_ = nullptr;
  AuditLogView* audit_view_ = nullptr;
  QDialog* sftp_window_ = nullptr;
  QDialog* audit_window_ = nullptr;

  QLabel* connection_status_label_ = nullptr;
  QLabel* session_count_label_ = nullptr;
  QLabel* footer_mode_label_ = nullptr;
  QLabel* footer_sessions_label_ = nullptr;

  QAction* edit_action_ = nullptr;
  QAction* open_sftp_action_ = nullptr;
  QAction* open_audit_action_ = nullptr;
  QAction* auto_hostsig_action_ = nullptr;
  QAction* strict_hostsig_action_ = nullptr;
  QAction* compat_hostsig_action_ = nullptr;

  bool auto_collapsed_navigation_ = false;
  bool navigation_forced_expanded_ = false;
};

}  // namespace gmssh
