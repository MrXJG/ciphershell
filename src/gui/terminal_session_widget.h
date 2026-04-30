#pragma once

#include "core/audit_logger.h"
#include "core/types.h"

#include <QByteArray>
#include <QPlainTextEdit>
#include <QWidget>

class QSocketNotifier;
class QProcess;
class QTimer;

namespace gmssh {

class TerminalSessionWidget : public QWidget {
  Q_OBJECT

 public:
  TerminalSessionWidget(
      QString session_name,
      ConnectionProfile profile,
      SessionSecrets secrets,
      SshLaunchPlan launch_plan,
      AuditLogger* audit_logger,
      QWidget* parent = nullptr);

  ~TerminalSessionWidget() override;

  const QString& sessionName() const;
  const ConnectionProfile& profile() const;
  const SessionSecrets& secrets() const;

 signals:
  void sessionClosed(const QString& session_name);

 private:
  enum class EscapeParseState {
    Text,
    Escape,
    Csi,
    Osc,
    OscEscape,
    StringTerminated,
    StringTerminatedEscape
  };

  void appendOutput(const QString& text);
  void appendTerminalText(const QString& text);
  void renderTerminalBuffer();
  void putTerminalChar(QChar ch);
  void clearCurrentLineRight();
  QString sanitizeTerminalOutput(const QString& text);
  void startTerminalProcess();
  void writeTerminalInput(const QByteArray& data);
  void readTerminalOutput();
  void pollTerminalProcess();
  void closeTerminalProcess();
  void finishTerminalSession(int exit_code, bool normal_exit);
  void updateTerminalWindowSize();
  void auditInputBytes(const QByteArray& data);
  void flushPendingAuditInput();
  void auditTerminalOutput(const QString& text);
  void logAuditEvent(const QString& event_name, QJsonObject details = {}) const;
  void cleanup();

  QString session_name_;
  QString session_audit_id_;
  ConnectionProfile profile_;
  SessionSecrets secrets_;
  SshLaunchPlan launch_plan_;
  AuditLogger* audit_logger_;

  QPlainTextEdit* output_view_ = nullptr;
  QSocketNotifier* pty_read_notifier_ = nullptr;
  QProcess* terminal_process_ = nullptr;
  QTimer* child_watch_timer_ = nullptr;

  int pty_master_fd_ = -1;
  qint64 child_pid_ = -1;
  bool session_closed_emitted_ = false;
  bool sensitive_input_active_ = false;
  bool audit_in_escape_sequence_ = false;
  QByteArray pending_audit_input_;
  QString csi_sequence_;
  QStringList terminal_lines_;
  int cursor_row_ = 0;
  int cursor_col_ = 0;
  EscapeParseState escape_parse_state_ = EscapeParseState::Text;
};

}  // namespace gmssh
