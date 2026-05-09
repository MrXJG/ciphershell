#pragma once

#include "core/audit_logger.h"
#include "core/types.h"

#include <QByteArray>
#include <QPlainTextEdit>
#include <QWidget>

class QSocketNotifier;
class QProcess;
class QTimer;
class QKeyEvent;
class QWheelEvent;
#if defined(GMSSH_HAS_WEBTERMINAL)
class QWebEngineView;
class QWebChannel;
#endif

namespace gmssh {

class SshEngineAdapter;

class TerminalSessionWidget : public QWidget {
  Q_OBJECT

 public:
  TerminalSessionWidget(
      QString session_name,
      ConnectionProfile profile,
      SessionSecrets secrets,
      SshLaunchPlan launch_plan,
      AuditLogger* audit_logger,
      SshEngineAdapter* engine_adapter = nullptr,
      QWidget* parent = nullptr);

  ~TerminalSessionWidget() override;

  const QString& sessionName() const;
  const ConnectionProfile& profile() const;
  const SessionSecrets& secrets() const;
  QString terminalText() const;
  void requestClearScreen();
  void activateInputFocus();

 signals:
  void sessionClosed(const QString& session_name);

 private:
  enum class EscapeParseState {
    Text,
    Escape,
    EscapeCharset,
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
  void ensureCursorRowExists(int row);
  void moveCursorToRowCol(int row, int col);
  void clearCurrentLineRight();
  void applyEraseInDisplay(int mode);
  void applyEraseInLine(int mode);
  void trimToTerminalViewportRows();
  void scrollToCursor();
  QString sanitizeTerminalOutput(const QString& text);
  void startTerminalProcess();
  void writeTerminalInput(const QByteArray& data);
  void readTerminalOutput();
  void pollTerminalProcess();
  void closeTerminalProcess();
  void finishTerminalSession(int exit_code, bool normal_exit);
  void updateTerminalWindowSize();
  bool handleZoomKeyPress(QKeyEvent* event);
  bool handleZoomWheel(QWheelEvent* event);
  void adjustTerminalFontSize(int delta);
  void resetTerminalFontSize();
  void applyTerminalFontSize(int point_size, bool update_reset_baseline = false);
  void auditInputBytes(const QByteArray& data);
  void flushPendingAuditInput();
  void auditTerminalOutput(const QString& text);
  void logAuditEvent(const QString& event_name, QJsonObject details = {}) const;
  void cleanup();
  void scrollToBottom();
  bool shouldAutoRetryTransientNetworkFailure(int exit_code) const;
#if defined(GMSSH_HAS_WEBTERMINAL)
  void beginWebTerminalBootstrap();
  void scheduleWebTerminalBootstrapTimeout();
  void handleWebTerminalLoadFinished(bool ok);
  void handleWebTerminalBootstrapTimeout();
  void failWebTerminalBootstrap(const QString& reason);
#endif

  QString session_name_;
  QString session_audit_id_;
  ConnectionProfile profile_;
  SessionSecrets secrets_;
  SshLaunchPlan launch_plan_;
  AuditLogger* audit_logger_;
  SshEngineAdapter* engine_adapter_ = nullptr;

  QPlainTextEdit* output_view_ = nullptr;
#if defined(GMSSH_HAS_WEBTERMINAL)
  QWebEngineView* web_terminal_view_ = nullptr;
  QWebChannel* web_channel_ = nullptr;
  QObject* web_terminal_bridge_ = nullptr;
  bool use_web_terminal_ = false;
  bool web_terminal_ready_ = false;
  int web_terminal_bootstrap_attempt_ = 0;
  QTimer* web_terminal_bootstrap_timer_ = nullptr;
  QStringList pending_web_output_;
#endif
  QSocketNotifier* pty_read_notifier_ = nullptr;
  QProcess* terminal_process_ = nullptr;
  QTimer* child_watch_timer_ = nullptr;
  QTimer* render_coalesce_timer_ = nullptr;

  int pty_master_fd_ = -1;
  qint64 child_pid_ = -1;
  bool session_closed_emitted_ = false;
  bool retry_attempted_ = false;
  bool user_input_detected_ = false;
  bool sensitive_input_active_ = false;
  bool audit_in_escape_sequence_ = false;
  QByteArray pending_audit_input_;
  QString terminal_transcript_;
  QString csi_sequence_;
  QStringList terminal_lines_;
  int cursor_row_ = 0;
  int cursor_col_ = 0;
  int saved_cursor_row_ = 0;
  int saved_cursor_col_ = 0;
  bool has_saved_cursor_ = false;
  bool follow_output_tail_ = true;
  bool suppress_scroll_tracking_ = false;
  bool in_alternate_screen_ = false;
  bool in_screen_repaint_mode_ = false;
  int non_repaint_chunks_in_screen_mode_ = 0;
  int terminal_rows_ = 24;
  int terminal_cols_ = 80;
  int terminal_font_size_ = 13;
  int default_terminal_font_size_ = 13;
  bool render_pending_ = false;
  EscapeParseState escape_parse_state_ = EscapeParseState::Text;
};

}  // namespace gmssh
