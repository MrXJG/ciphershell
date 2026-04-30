#include "gui/terminal_session_widget.h"

#include <QClipboard>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonObject>
#include <QKeyEvent>
#include <QProcess>
#include <QProcessEnvironment>
#include <QScrollBar>
#include <QSocketNotifier>
#include <QStandardPaths>
#include <QTextCursor>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <functional>
#include <utility>
#include <vector>

#if defined(Q_OS_UNIX)
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#if defined(Q_OS_DARWIN)
#include <util.h>
#else
#include <pty.h>
#endif
extern char** environ;
#endif

namespace gmssh {
namespace {

constexpr ushort kClearLineRightMarker = 0xE000;
constexpr ushort kClearWholeLineMarker = 0xE001;
constexpr int kMaxTerminalLines = 3000;

QString firstAvailableFontFamily(const QStringList& preferred_families, const QString& fallback) {
  const auto families = QFontDatabase::families();
  for (const auto& preferred : preferred_families) {
    for (const auto& family : families) {
      if (family.compare(preferred, Qt::CaseInsensitive) == 0) {
        return family;
      }
    }
  }
  return fallback;
}

QString fallbackReasonZh(const QString& reason) {
  if (reason == QStringLiteral("local_client_gm_option_unsupported")) {
    return QStringLiteral("本地 SSH 引擎不支持国密算法参数");
  }
  if (reason == QStringLiteral("gm_probe_algorithm_mismatch")) {
    return QStringLiteral("服务端未接受当前国密算法参数");
  }
  if (reason == QStringLiteral("strict_policy_blocked_compatibility_bypass")) {
    return QStringLiteral("严格模式已阻断旧版 ecgm 主机签名适配");
  }
  return reason.isEmpty() ? QStringLiteral("未知原因") : reason;
}

QString engineFallbackReasonZh(const QString& reason) {
  if (reason == QStringLiteral("gm_probe_mac_incorrect_modern_to_legacy")) {
    return QStringLiteral("检测到 ecgm 场景下 MAC incorrect，切换到旧版国密引擎");
  }
  if (reason == QStringLiteral("gm_probe_verify_kex_internal_legacy_to_modern")) {
    return QStringLiteral("检测到 sm2-sm3 场景 verify KEX internal error，切换到现代引擎");
  }
  return reason.isEmpty() ? QStringLiteral("未知原因") : reason;
}

QString selectedModeZh(AlgorithmMode mode) {
  switch (mode) {
    case AlgorithmMode::GmOnly:
      return QStringLiteral("国密 SSH（sm2/ecgm + sm4 + hmac-sm3）");
    case AlgorithmMode::StandardOnly:
      return QStringLiteral("标准 SSH");
    case AlgorithmMode::Auto:
      return QStringLiteral("自动协商 SSH");
  }
  return QStringLiteral("未知");
}

QString displaySafeDiagnostics(QString text) {
  text.replace(
      QStringLiteral("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility"),
      QStringLiteral("ecgm-sm2-sm3 旧版国密主机签名适配已启用"));
  return text.replace(
      QStringLiteral("ecgm-sm2-sm3 legacy GM host-signature adaptation enabled"),
      QStringLiteral("ecgm-sm2-sm3 旧版国密主机签名适配已启用"));
}

QString terminalControlName(uchar byte) {
  switch (byte) {
    case 0x03:
      return QStringLiteral("CTRL_C");
    case 0x04:
      return QStringLiteral("CTRL_D");
    case 0x0c:
      return QStringLiteral("CTRL_L");
    case 0x1a:
      return QStringLiteral("CTRL_Z");
    default:
      return QStringLiteral("CTRL_%1").arg(static_cast<int>(byte));
  }
}

bool looksLikeSensitivePrompt(const QString& text) {
  const auto lower = text.toLower();
  const bool has_sensitive_word = lower.contains(QStringLiteral("password")) ||
                                  lower.contains(QStringLiteral("passphrase")) ||
                                  text.contains(QStringLiteral("密码")) ||
                                  text.contains(QStringLiteral("口令"));
  return has_sensitive_word &&
         (text.contains(QChar::fromLatin1(':')) || text.contains(QStringLiteral("：")));
}

QString cappedAuditText(QString text, bool* truncated) {
  constexpr qsizetype kMaxAuditTextChars = 12000;
  if (truncated != nullptr) {
    *truncated = false;
  }
  if (text.size() <= kMaxAuditTextChars) {
    return text;
  }
  if (truncated != nullptr) {
    *truncated = true;
  }
  return text.left(kMaxAuditTextChars);
}

QString stripTerminalMarkers(QString text) {
  text.remove(QChar(kClearLineRightMarker));
  text.remove(QChar(kClearWholeLineMarker));
  return text;
}

#if defined(Q_OS_UNIX)
QByteArray fileNameBytes(const QString& value) {
  return QFile::encodeName(value);
}

QString resolveExecutablePath(const QString& program, const QProcessEnvironment& env) {
  if (program.contains(QChar::fromLatin1('/'))) {
    return program;
  }

  const auto env_path = env.value(QStringLiteral("PATH"));
  QStringList search_paths;
  if (!env_path.isEmpty()) {
    search_paths = env_path.split(QChar::fromLatin1(':'), Qt::SkipEmptyParts);
  }

  auto resolved = QStandardPaths::findExecutable(program, search_paths);
  if (resolved.isEmpty()) {
    resolved = QStandardPaths::findExecutable(program);
  }
  return resolved.isEmpty() ? program : resolved;
}
#endif

class TerminalOutputView final : public QPlainTextEdit {
 public:
  explicit TerminalOutputView(QWidget* parent = nullptr) : QPlainTextEdit(parent) {
    setReadOnly(true);
    setUndoRedoEnabled(false);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFocusPolicy(Qt::StrongFocus);
    setCursorWidth(2);
  }

  void setInputHandler(std::function<void(QByteArray)> handler) {
    input_handler_ = std::move(handler);
  }

  void setResizeHandler(std::function<void()> handler) {
    resize_handler_ = std::move(handler);
  }

 protected:
  void keyPressEvent(QKeyEvent* event) override {
    if (event->matches(QKeySequence::Copy) ||
        ((event->modifiers() & Qt::ControlModifier) &&
         (event->modifiers() & Qt::ShiftModifier) && event->key() == Qt::Key_C)) {
      copy();
      return;
    }

    if (event->matches(QKeySequence::Paste) ||
        ((event->modifiers() & Qt::ControlModifier) &&
         (event->modifiers() & Qt::ShiftModifier) && event->key() == Qt::Key_V)) {
      const auto* clipboard = QGuiApplication::clipboard();
      if (clipboard != nullptr) {
        sendData(clipboard->text().toUtf8());
      }
      return;
    }

    const auto modifiers = event->modifiers();
    if ((modifiers & Qt::ControlModifier) && !(modifiers & Qt::AltModifier) &&
        !(modifiers & Qt::MetaModifier) && !(modifiers & Qt::ShiftModifier)) {
      const auto key = event->key();
      if (key >= Qt::Key_A && key <= Qt::Key_Z) {
        const char control = static_cast<char>(key - Qt::Key_A + 1);
        sendData(QByteArray(1, control));
        return;
      }
      if (key == Qt::Key_BracketLeft) {
        sendData(QByteArray(1, 0x1b));
        return;
      }
      if (key == Qt::Key_Backslash) {
        sendData(QByteArray(1, 0x1c));
        return;
      }
      if (key == Qt::Key_BracketRight) {
        sendData(QByteArray(1, 0x1d));
        return;
      }
      if (key == Qt::Key_6) {
        sendData(QByteArray(1, 0x1e));
        return;
      }
      if (key == Qt::Key_Minus) {
        sendData(QByteArray(1, 0x1f));
        return;
      }
    }

    switch (event->key()) {
      case Qt::Key_Return:
      case Qt::Key_Enter:
        sendData(QByteArray("\r"));
        return;
      case Qt::Key_Backspace:
        sendData(QByteArray(1, 0x7f));
        return;
      case Qt::Key_Delete:
        sendData(QByteArray("\x1b[3~"));
        return;
      case Qt::Key_Tab:
        sendData(QByteArray("\t"));
        return;
      case Qt::Key_Escape:
        sendData(QByteArray(1, 0x1b));
        return;
      case Qt::Key_Left:
        sendData(QByteArray("\x1b[D"));
        return;
      case Qt::Key_Right:
        sendData(QByteArray("\x1b[C"));
        return;
      case Qt::Key_Up:
        sendData(QByteArray("\x1b[A"));
        return;
      case Qt::Key_Down:
        sendData(QByteArray("\x1b[B"));
        return;
      case Qt::Key_Home:
        sendData(QByteArray("\x1b[H"));
        return;
      case Qt::Key_End:
        sendData(QByteArray("\x1b[F"));
        return;
      case Qt::Key_PageUp:
        sendData(QByteArray("\x1b[5~"));
        return;
      case Qt::Key_PageDown:
        sendData(QByteArray("\x1b[6~"));
        return;
      default:
        break;
    }

    if (!event->text().isEmpty() && !(modifiers & Qt::MetaModifier)) {
      sendData(event->text().toUtf8());
      return;
    }

    QPlainTextEdit::keyPressEvent(event);
  }

  void resizeEvent(QResizeEvent* event) override {
    QPlainTextEdit::resizeEvent(event);
    if (resize_handler_) {
      resize_handler_();
    }
  }

 private:
  void sendData(const QByteArray& data) {
    if (!data.isEmpty() && input_handler_) {
      input_handler_(data);
    }
  }

  std::function<void(QByteArray)> input_handler_;
  std::function<void()> resize_handler_;
};

}  // namespace

TerminalSessionWidget::TerminalSessionWidget(
    QString session_name,
    ConnectionProfile profile,
    SessionSecrets secrets,
    SshLaunchPlan launch_plan,
    AuditLogger* audit_logger,
    QWidget* parent)
    : QWidget(parent),
      session_name_(std::move(session_name)),
      session_audit_id_(QUuid::createUuid().toString(QUuid::WithoutBraces)),
      profile_(std::move(profile)),
      secrets_(std::move(secrets)),
      launch_plan_(std::move(launch_plan)),
      audit_logger_(audit_logger) {
  terminal_lines_.push_back(QString());

  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(6, 6, 6, 6);
  layout->setSpacing(8);

  auto* terminal_view = new TerminalOutputView(this);
  output_view_ = terminal_view;
  output_view_->setObjectName(QStringLiteral("terminalOutputView"));
  output_view_->setMinimumHeight(240);

  auto terminal_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  terminal_font.setFamily(firstAvailableFontFamily(
      QStringList{
          QStringLiteral("Cascadia Mono"),
          QStringLiteral("Consolas"),
          QStringLiteral("SF Mono"),
          QStringLiteral("Menlo"),
      },
      terminal_font.family()));
  if (terminal_font.pointSize() < 13) {
    terminal_font.setPointSize(13);
  }
  terminal_font.setStyleHint(QFont::TypeWriter);
  terminal_font.setStyleStrategy(QFont::PreferAntialias);
  output_view_->setFont(terminal_font);

  terminal_view->setInputHandler([this](const QByteArray& data) {
    writeTerminalInput(data);
  });
  terminal_view->setResizeHandler([this]() {
    updateTerminalWindowSize();
  });

  layout->addWidget(output_view_, 1);

  appendOutput(QStringLiteral("[系统] 正在建立连接，请稍候...\n"));
  appendOutput(QStringLiteral("[系统] 当前 SSH 引擎：%1\n").arg(launch_plan_.program));
  appendOutput(QStringLiteral("[系统] 连接方式：%1\n").arg(selectedModeZh(launch_plan_.selected_mode)));
#if defined(Q_OS_UNIX)
  appendOutput(
      QStringLiteral("[系统] 终端模式：内置 PTY，键盘输入直接进入远端 shell；Tab/方向键由远端处理\n"));
#else
  appendOutput(
      QStringLiteral("[系统] 终端模式：Windows 管道终端，键盘输入进入 SSH 进程；远端由 ssh -tt 分配交互终端\n"));
#endif
  appendOutput(
      QStringLiteral("[系统] 国密主机签名校验：%1\n")
          .arg(launch_plan_.gm_hostsig_compatibility_bypass
                   ? QStringLiteral("旧版国密适配（降低校验强度）")
                   : QStringLiteral("严格校验（推荐）")));
  if (launch_plan_.fallback_used) {
    appendOutput(
        QStringLiteral("[系统] 已从国密参数回退到常规参数，原因：%1\n")
            .arg(fallbackReasonZh(launch_plan_.fallback_reason)));
  }
  if (launch_plan_.engine_fallback_used) {
    appendOutput(
        QStringLiteral("[系统] 已自动切换 SSH 引擎：\n  from: %1\n  to:   %2\n  reason: %3\n")
            .arg(launch_plan_.engine_fallback_from,
                 launch_plan_.engine_fallback_to,
                 engineFallbackReasonZh(launch_plan_.engine_fallback_reason)));
  }

  if (!launch_plan_.ok) {
    appendOutput(QStringLiteral("[错误] 启动失败：%1\n").arg(launch_plan_.error));
    return;
  }

  startTerminalProcess();
}

TerminalSessionWidget::~TerminalSessionWidget() {
  closeTerminalProcess();
  cleanup();
}

const QString& TerminalSessionWidget::sessionName() const {
  return session_name_;
}

const ConnectionProfile& TerminalSessionWidget::profile() const {
  return profile_;
}

const SessionSecrets& TerminalSessionWidget::secrets() const {
  return secrets_;
}

void TerminalSessionWidget::appendOutput(const QString& text) {
  if (text.isEmpty()) {
    return;
  }

  const auto sanitized = sanitizeTerminalOutput(text);
  if (sanitized.isEmpty()) {
    return;
  }

  if (looksLikeSensitivePrompt(sanitized)) {
    sensitive_input_active_ = true;
  }

  auditTerminalOutput(sanitized);

  if (!launch_plan_.gm_hostsig_compatibility_bypass &&
      sanitized.contains(
          QStringLiteral("host signature verify bypass enabled for compatibility"),
          Qt::CaseInsensitive)) {
    appendTerminalText(sanitized);
    appendTerminalText(
        QStringLiteral(
            "\n[错误] 严格模式已阻断旧版国密主机签名适配，请在“安全”菜单切换为“国密旧版服务端适配（降低校验强度）”后重试。\n"));
    closeTerminalProcess();
    finishTerminalSession(-1, false);
    return;
  }

  if (!launch_plan_.gm_hostsig_compatibility_bypass &&
      sanitized.contains(
          QStringLiteral("legacy GM host-signature adaptation enabled"),
          Qt::CaseInsensitive)) {
    appendTerminalText(sanitized);
    appendTerminalText(
        QStringLiteral(
            "\n[错误] 严格模式已阻断旧版国密主机签名适配，请在“安全”菜单切换为“国密旧版服务端适配（降低校验强度）”后重试。\n"));
    closeTerminalProcess();
    finishTerminalSession(-1, false);
    return;
  }

  appendTerminalText(sanitized);
}

void TerminalSessionWidget::appendTerminalText(const QString& text) {
  if (output_view_ == nullptr) {
    return;
  }

  for (const auto ch : text) {
    if (ch.unicode() == kClearLineRightMarker || ch.unicode() == kClearWholeLineMarker) {
      if (ch.unicode() == kClearWholeLineMarker) {
        terminal_lines_[cursor_row_].clear();
        cursor_col_ = 0;
      }
      clearCurrentLineRight();
      continue;
    }
    if (ch == QChar::fromLatin1('\r')) {
      cursor_col_ = 0;
      continue;
    }
    if (ch == QChar::fromLatin1('\n')) {
      ++cursor_row_;
      cursor_col_ = 0;
      if (cursor_row_ >= terminal_lines_.size()) {
        terminal_lines_.push_back(QString());
      }
      continue;
    }
    putTerminalChar(ch);
  }

  renderTerminalBuffer();
}

void TerminalSessionWidget::renderTerminalBuffer() {
  while (terminal_lines_.size() > kMaxTerminalLines) {
    terminal_lines_.removeFirst();
    cursor_row_ = std::max(0, cursor_row_ - 1);
  }

  output_view_->setPlainText(terminal_lines_.join(QChar::fromLatin1('\n')));

  auto cursor = output_view_->textCursor();
  cursor.movePosition(QTextCursor::Start);
  for (int row = 0; row < cursor_row_; ++row) {
    cursor.movePosition(QTextCursor::Down);
  }
  cursor.movePosition(QTextCursor::StartOfLine);
  const auto column = std::min(cursor_col_, static_cast<int>(terminal_lines_.value(cursor_row_).size()));
  for (int col = 0; col < column; ++col) {
    cursor.movePosition(QTextCursor::Right);
  }
  output_view_->setTextCursor(cursor);
  output_view_->ensureCursorVisible();
}

void TerminalSessionWidget::putTerminalChar(QChar ch) {
  if (terminal_lines_.isEmpty()) {
    terminal_lines_.push_back(QString());
  }
  cursor_row_ = std::clamp(cursor_row_, 0, static_cast<int>(terminal_lines_.size()) - 1);

  if (ch == QChar::fromLatin1('\b') || ch.unicode() == 0x7f) {
    if (cursor_col_ > 0) {
      auto& line = terminal_lines_[cursor_row_];
      --cursor_col_;
      if (cursor_col_ < line.size()) {
        line.remove(cursor_col_, 1);
      }
    }
    return;
  }

  if (ch == QChar::fromLatin1('\t')) {
    const int spaces = 8 - (cursor_col_ % 8);
    for (int i = 0; i < spaces; ++i) {
      putTerminalChar(QChar::fromLatin1(' '));
    }
    return;
  }

  auto& line = terminal_lines_[cursor_row_];
  while (line.size() < cursor_col_) {
    line.append(QChar::fromLatin1(' '));
  }
  if (cursor_col_ < line.size()) {
    line[cursor_col_] = ch;
  } else {
    line.append(ch);
  }
  ++cursor_col_;
}

void TerminalSessionWidget::clearCurrentLineRight() {
  if (terminal_lines_.isEmpty()) {
    return;
  }
  auto& line = terminal_lines_[cursor_row_];
  if (cursor_col_ < line.size()) {
    line.truncate(cursor_col_);
  }
}

QString TerminalSessionWidget::sanitizeTerminalOutput(const QString& text) {
  QString cleaned;
  cleaned.reserve(text.size());

  for (const auto ch : text) {
    const auto code = ch.unicode();
    switch (escape_parse_state_) {
      case EscapeParseState::Text:
        if (code == 0x1B) {
          escape_parse_state_ = EscapeParseState::Escape;
          continue;
        }
        if (code == 0x9B) {
          escape_parse_state_ = EscapeParseState::Csi;
          continue;
        }
        if ((code < 0x20 && ch != QChar::fromLatin1('\n') &&
             ch != QChar::fromLatin1('\r') && ch != QChar::fromLatin1('\t') &&
             ch != QChar::fromLatin1('\b')) ||
            (code >= 0x80 && code <= 0x9F)) {
          continue;
        }
        cleaned.append(ch);
        break;

      case EscapeParseState::Escape:
        if (ch == QChar::fromLatin1('[') || code == 0x9B) {
          escape_parse_state_ = EscapeParseState::Csi;
          continue;
        }
        if (ch == QChar::fromLatin1(']')) {
          escape_parse_state_ = EscapeParseState::Osc;
          continue;
        }
        if (ch == QChar::fromLatin1('P') || ch == QChar::fromLatin1('X') ||
            ch == QChar::fromLatin1('^') || ch == QChar::fromLatin1('_')) {
          escape_parse_state_ = EscapeParseState::StringTerminated;
          continue;
        }
        escape_parse_state_ = EscapeParseState::Text;
        break;

      case EscapeParseState::Csi:
        if (code >= 0x40 && code <= 0x7E) {
          if (ch == QChar::fromLatin1('K')) {
            cleaned.append(
                csi_sequence_.contains(QChar::fromLatin1('2'))
                    ? QChar(kClearWholeLineMarker)
                    : QChar(kClearLineRightMarker));
          }
          csi_sequence_.clear();
          escape_parse_state_ = EscapeParseState::Text;
        } else {
          csi_sequence_.append(ch);
        }
        break;

      case EscapeParseState::Osc:
        if (ch == QChar::fromLatin1('\a')) {
          escape_parse_state_ = EscapeParseState::Text;
          continue;
        }
        if (code == 0x1B) {
          escape_parse_state_ = EscapeParseState::OscEscape;
          continue;
        }
        break;

      case EscapeParseState::OscEscape:
        if (ch == QChar::fromLatin1('\\') || ch == QChar::fromLatin1('\a')) {
          escape_parse_state_ = EscapeParseState::Text;
          continue;
        }
        escape_parse_state_ = EscapeParseState::Osc;
        break;

      case EscapeParseState::StringTerminated:
        if (code == 0x1B) {
          escape_parse_state_ = EscapeParseState::StringTerminatedEscape;
        }
        break;

      case EscapeParseState::StringTerminatedEscape:
        if (ch == QChar::fromLatin1('\\')) {
          escape_parse_state_ = EscapeParseState::Text;
          continue;
        }
        escape_parse_state_ = EscapeParseState::StringTerminated;
        break;
    }
  }

  return displaySafeDiagnostics(cleaned);
}

void TerminalSessionWidget::startTerminalProcess() {
#if defined(Q_OS_UNIX)
  auto env = launch_plan_.environment;
  if (env.isEmpty()) {
    env = QProcessEnvironment::systemEnvironment();
  }
  if (env.value(QStringLiteral("TERM")).trimmed().isEmpty()) {
    env.insert(QStringLiteral("TERM"), QStringLiteral("xterm-256color"));
  }
  if (env.value(QStringLiteral("LANG")).trimmed().isEmpty()) {
    env.insert(QStringLiteral("LANG"), QStringLiteral("en_US.UTF-8"));
  }

  const auto executable_path = resolveExecutablePath(launch_plan_.program, env);
  const auto executable_bytes = fileNameBytes(executable_path);

  std::vector<QByteArray> argv_storage;
  argv_storage.reserve(static_cast<size_t>(launch_plan_.arguments.size()) + 1);
  argv_storage.push_back(fileNameBytes(QFileInfo(executable_path).fileName()));
  for (const auto& argument : launch_plan_.arguments) {
    argv_storage.push_back(argument.toLocal8Bit());
  }

  std::vector<char*> argv;
  argv.reserve(argv_storage.size() + 1);
  for (auto& item : argv_storage) {
    argv.push_back(item.data());
  }
  argv.push_back(nullptr);

  const auto env_list = env.toStringList();
  std::vector<QByteArray> env_storage;
  env_storage.reserve(static_cast<size_t>(env_list.size()));
  for (const auto& item : env_list) {
    env_storage.push_back(item.toLocal8Bit());
  }
  std::vector<char*> envp;
  envp.reserve(env_storage.size() + 1);
  for (auto& item : env_storage) {
    envp.push_back(item.data());
  }
  envp.push_back(nullptr);

  struct winsize window_size {};
  const QFontMetrics metrics(output_view_->font());
  window_size.ws_col = static_cast<unsigned short>(
      std::max(20, output_view_->viewport()->width() / std::max(1, metrics.horizontalAdvance(QChar::fromLatin1('M')))));
  window_size.ws_row = static_cast<unsigned short>(
      std::max(6, output_view_->viewport()->height() / std::max(1, metrics.lineSpacing())));

  int master_fd = -1;
  const auto pid = ::forkpty(&master_fd, nullptr, nullptr, &window_size);
  if (pid < 0) {
    appendOutput(QStringLiteral("[错误] PTY 启动失败：%1\n").arg(QString::fromLocal8Bit(std::strerror(errno))));
    return;
  }

  if (pid == 0) {
    ::execve(executable_bytes.constData(), argv.data(), envp.empty() ? environ : envp.data());
    ::_exit(127);
  }

  pty_master_fd_ = master_fd;
  child_pid_ = pid;
  const int flags = ::fcntl(pty_master_fd_, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(pty_master_fd_, F_SETFL, flags | O_NONBLOCK);
  }

  pty_read_notifier_ = new QSocketNotifier(pty_master_fd_, QSocketNotifier::Read, this);
  connect(pty_read_notifier_, &QSocketNotifier::activated, this, [this]() {
    readTerminalOutput();
  });

  child_watch_timer_ = new QTimer(this);
  child_watch_timer_->setInterval(500);
  connect(child_watch_timer_, &QTimer::timeout, this, &TerminalSessionWidget::pollTerminalProcess);
  child_watch_timer_->start();

  appendOutput(QStringLiteral("[系统] SSH 进程已在 PTY 中启动，等待服务器响应...\n"));
  output_view_->setFocus();

  logAuditEvent(
      QStringLiteral("session_started"),
      QJsonObject{
          {QStringLiteral("ssh_program"), executable_path},
          {QStringLiteral("selected_mode"), toString(launch_plan_.selected_mode)},
          {QStringLiteral("terminal_mode"), QStringLiteral("pty")},
      });
#else
  auto env = launch_plan_.environment;
  if (env.isEmpty()) {
    env = QProcessEnvironment::systemEnvironment();
  }
  if (env.value(QStringLiteral("TERM")).trimmed().isEmpty()) {
    env.insert(QStringLiteral("TERM"), QStringLiteral("xterm-256color"));
  }
  if (env.value(QStringLiteral("LANG")).trimmed().isEmpty()) {
    env.insert(QStringLiteral("LANG"), QStringLiteral("en_US.UTF-8"));
  }

  auto* process = new QProcess(this);
  terminal_process_ = process;
  process->setProgram(launch_plan_.program);
  process->setArguments(launch_plan_.arguments);
  process->setProcessEnvironment(env);
  process->setProcessChannelMode(QProcess::SeparateChannels);

  const auto drain_output = [this, process]() {
    if (terminal_process_ != process) {
      return;
    }
    const auto stdout_data = process->readAllStandardOutput();
    if (!stdout_data.isEmpty()) {
      appendOutput(QString::fromUtf8(stdout_data));
    }
    const auto stderr_data = process->readAllStandardError();
    if (!stderr_data.isEmpty()) {
      appendOutput(QString::fromUtf8(stderr_data));
    }
  };

  connect(process, &QProcess::readyReadStandardOutput, this, drain_output);
  connect(process, &QProcess::readyReadStandardError, this, drain_output);
  connect(process, &QProcess::started, this, [this]() {
    appendOutput(QStringLiteral("[系统] SSH 进程已在 Windows 管道终端模式启动，等待服务器响应...\n"));
    output_view_->setFocus();
    logAuditEvent(
        QStringLiteral("session_started"),
        QJsonObject{
            {QStringLiteral("ssh_program"), launch_plan_.program},
            {QStringLiteral("selected_mode"), toString(launch_plan_.selected_mode)},
            {QStringLiteral("terminal_mode"), QStringLiteral("windows_pipe")},
        });
  });
  connect(
      process,
      &QProcess::errorOccurred,
      this,
      [this, process](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart || terminal_process_ != process) {
          return;
        }
        appendOutput(QStringLiteral("[错误] Windows 管道终端启动失败：%1\n").arg(process->errorString()));
        terminal_process_ = nullptr;
        process->deleteLater();
        finishTerminalSession(-1, false);
      });
  connect(
      process,
      QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
      this,
      [this, process](int exit_code, QProcess::ExitStatus status) {
        if (terminal_process_ != process) {
          return;
        }
        const auto stdout_data = process->readAllStandardOutput();
        if (!stdout_data.isEmpty()) {
          appendOutput(QString::fromUtf8(stdout_data));
        }
        const auto stderr_data = process->readAllStandardError();
        if (!stderr_data.isEmpty()) {
          appendOutput(QString::fromUtf8(stderr_data));
        }
        terminal_process_ = nullptr;
        process->deleteLater();
        finishTerminalSession(exit_code, status == QProcess::NormalExit);
      });

  process->start();
#endif
}

void TerminalSessionWidget::writeTerminalInput(const QByteArray& data) {
#if defined(Q_OS_UNIX)
  if (pty_master_fd_ < 0 || data.isEmpty()) {
    return;
  }

  auditInputBytes(data);

  qsizetype offset = 0;
  while (offset < data.size()) {
    const auto written = ::write(
        pty_master_fd_,
        data.constData() + offset,
        static_cast<size_t>(data.size() - offset));
    if (written > 0) {
      offset += written;
      continue;
    }
    if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      continue;
    }
    break;
  }
#else
  if (terminal_process_ == nullptr || data.isEmpty() ||
      terminal_process_->state() != QProcess::Running) {
    return;
  }

  auditInputBytes(data);
  terminal_process_->write(data);
#endif
}

void TerminalSessionWidget::readTerminalOutput() {
#if defined(Q_OS_UNIX)
  if (pty_master_fd_ < 0) {
    return;
  }

  char buffer[8192];
  while (true) {
    const auto count = ::read(pty_master_fd_, buffer, sizeof(buffer));
    if (count > 0) {
      appendOutput(QString::fromUtf8(buffer, static_cast<qsizetype>(count)));
      continue;
    }
    if (count == 0) {
      pollTerminalProcess();
      return;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;
    }
    appendOutput(QStringLiteral("\n[错误] PTY 读取失败：%1\n").arg(QString::fromLocal8Bit(std::strerror(errno))));
    pollTerminalProcess();
    return;
  }
#else
  if (terminal_process_ == nullptr) {
    return;
  }
  const auto stdout_data = terminal_process_->readAllStandardOutput();
  if (!stdout_data.isEmpty()) {
    appendOutput(QString::fromUtf8(stdout_data));
  }
  const auto stderr_data = terminal_process_->readAllStandardError();
  if (!stderr_data.isEmpty()) {
    appendOutput(QString::fromUtf8(stderr_data));
  }
#endif
}

void TerminalSessionWidget::pollTerminalProcess() {
#if defined(Q_OS_UNIX)
  if (child_pid_ <= 0) {
    return;
  }

  int status = 0;
  const auto result = ::waitpid(static_cast<pid_t>(child_pid_), &status, WNOHANG);
  if (result == 0 || (result < 0 && errno == EINTR)) {
    return;
  }
  if (result < 0) {
    finishTerminalSession(-1, false);
    return;
  }

  const bool normal_exit = WIFEXITED(status);
  const int exit_code = normal_exit ? WEXITSTATUS(status)
                                    : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1);
  child_pid_ = -1;
  if (pty_read_notifier_ != nullptr) {
    pty_read_notifier_->setEnabled(false);
  }
  if (pty_master_fd_ >= 0) {
    ::close(pty_master_fd_);
    pty_master_fd_ = -1;
  }
  finishTerminalSession(exit_code, normal_exit);
#else
  if (terminal_process_ != nullptr && terminal_process_->state() == QProcess::NotRunning) {
    finishTerminalSession(terminal_process_->exitCode(),
                          terminal_process_->exitStatus() == QProcess::NormalExit);
  }
#endif
}

void TerminalSessionWidget::closeTerminalProcess() {
#if defined(Q_OS_UNIX)
  if (pty_read_notifier_ != nullptr) {
    pty_read_notifier_->setEnabled(false);
    pty_read_notifier_->deleteLater();
    pty_read_notifier_ = nullptr;
  }
  if (child_watch_timer_ != nullptr) {
    child_watch_timer_->stop();
    child_watch_timer_->deleteLater();
    child_watch_timer_ = nullptr;
  }
  if (child_pid_ > 0) {
    ::kill(static_cast<pid_t>(child_pid_), SIGHUP);
    int status = 0;
    if (::waitpid(static_cast<pid_t>(child_pid_), &status, WNOHANG) == 0) {
      ::kill(static_cast<pid_t>(child_pid_), SIGTERM);
    }
    child_pid_ = -1;
  }
  if (pty_master_fd_ >= 0) {
    ::close(pty_master_fd_);
    pty_master_fd_ = -1;
  }
#else
  if (terminal_process_ != nullptr) {
    auto* process = terminal_process_;
    terminal_process_ = nullptr;
    process->disconnect(this);
    if (process->state() != QProcess::NotRunning) {
      process->terminate();
      if (!process->waitForFinished(1000)) {
        process->kill();
        process->waitForFinished(1000);
      }
    }
    process->deleteLater();
  }
#endif
}

void TerminalSessionWidget::finishTerminalSession(int exit_code, bool normal_exit) {
  if (session_closed_emitted_) {
    return;
  }
  session_closed_emitted_ = true;

  flushPendingAuditInput();

  appendOutput(
      QStringLiteral("\n[会话结束] 退出码=%1 状态=%2\n")
          .arg(exit_code)
          .arg(normal_exit ? QStringLiteral("正常") : QStringLiteral("异常")));
  logAuditEvent(
      QStringLiteral("session_closed"),
      QJsonObject{{QStringLiteral("exit_code"), exit_code},
                  {QStringLiteral("normal_exit"), normal_exit}});
  cleanup();
  emit sessionClosed(session_name_);
}

void TerminalSessionWidget::updateTerminalWindowSize() {
#if defined(Q_OS_UNIX)
  if (pty_master_fd_ < 0 || output_view_ == nullptr) {
    return;
  }

  const QFontMetrics metrics(output_view_->font());
  struct winsize size {};
  size.ws_col = static_cast<unsigned short>(
      std::max(20, output_view_->viewport()->width() / std::max(1, metrics.horizontalAdvance(QChar::fromLatin1('M')))));
  size.ws_row = static_cast<unsigned short>(
      std::max(6, output_view_->viewport()->height() / std::max(1, metrics.lineSpacing())));
  ::ioctl(pty_master_fd_, TIOCSWINSZ, &size);
#endif
}

void TerminalSessionWidget::auditInputBytes(const QByteArray& data) {
  if (profile_.audit_level == AuditLevel::Minimal || audit_logger_ == nullptr) {
    return;
  }

  for (const auto raw_byte : data) {
    const auto byte = static_cast<uchar>(raw_byte);
    if (audit_in_escape_sequence_) {
      if (byte >= 0x40 && byte <= 0x7e) {
        audit_in_escape_sequence_ = false;
      }
      continue;
    }

    if (byte == 0x1b) {
      audit_in_escape_sequence_ = true;
      continue;
    }

    if (byte == '\r' || byte == '\n') {
      flushPendingAuditInput();
      continue;
    }

    if (byte == 0x7f || byte == 0x08) {
      if (!pending_audit_input_.isEmpty()) {
        pending_audit_input_.chop(1);
      }
      continue;
    }

    if (byte == 0x03 || byte == 0x04 || byte == 0x0c || byte == 0x1a) {
      logAuditEvent(
          QStringLiteral("terminal_control_input"),
          QJsonObject{{QStringLiteral("control"), terminalControlName(byte)}});
      continue;
    }

    if (byte == '\t') {
      pending_audit_input_.append('\t');
      continue;
    }

    if (byte >= 0x20) {
      pending_audit_input_.append(static_cast<char>(byte));
    }
  }
}

void TerminalSessionWidget::flushPendingAuditInput() {
  if (profile_.audit_level == AuditLevel::Minimal || audit_logger_ == nullptr) {
    pending_audit_input_.clear();
    sensitive_input_active_ = false;
    return;
  }

  const auto input_text = QString::fromUtf8(pending_audit_input_).trimmed();
  pending_audit_input_.clear();
  if (input_text.isEmpty() && !sensitive_input_active_) {
    return;
  }

  if (sensitive_input_active_) {
    logAuditEvent(
        QStringLiteral("terminal_input"),
        QJsonObject{{QStringLiteral("redacted"), true},
                    {QStringLiteral("reason"), QStringLiteral("sensitive_prompt")}});
    sensitive_input_active_ = false;
    return;
  }

  logAuditEvent(
      QStringLiteral("terminal_input"),
      QJsonObject{{QStringLiteral("text"), input_text},
                  {QStringLiteral("redacted"), false}});
}

void TerminalSessionWidget::auditTerminalOutput(const QString& text) {
  if (profile_.audit_level == AuditLevel::Minimal || audit_logger_ == nullptr) {
    return;
  }

  const auto trimmed = text.trimmed();
  if (trimmed.isEmpty()) {
    return;
  }

  bool truncated = false;
  const auto capped = cappedAuditText(stripTerminalMarkers(text), &truncated);
  logAuditEvent(
      QStringLiteral("terminal_output"),
      QJsonObject{{QStringLiteral("text"), capped},
                  {QStringLiteral("truncated"), truncated}});
}

void TerminalSessionWidget::logAuditEvent(const QString& event_name, QJsonObject details) const {
  if (audit_logger_ == nullptr) {
    return;
  }

  details.insert(QStringLiteral("session"), session_name_);
  details.insert(QStringLiteral("session_id"), session_audit_id_);
  details.insert(QStringLiteral("profile"), profile_.name);
  details.insert(QStringLiteral("host"), profile_.host);
  details.insert(QStringLiteral("port"), profile_.port);
  details.insert(QStringLiteral("username"), profile_.username);
  audit_logger_->logEvent(event_name, details);
}

void TerminalSessionWidget::cleanup() {
  for (const auto& path : launch_plan_.cleanup_files) {
    QFile::remove(path);
  }
  launch_plan_.cleanup_files.clear();
}

}  // namespace gmssh
