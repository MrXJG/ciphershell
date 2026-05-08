#include "gui/terminal_session_widget.h"

#include "core/ssh_engine_adapter.h"

#include <QClipboard>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QIODevice>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPointer>
#include <QScrollBar>
#include <QSocketNotifier>
#include <QStandardPaths>
#include <QTextCursor>
#include <QTextOption>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <QVBoxLayout>
#if defined(GMSSH_HAS_WEBTERMINAL)
#include <QWebChannel>
#include <QWebEngineLoadingInfo>
#include <QWebEnginePage>
#include <QWebEngineSettings>
#include <QWebEngineView>
#endif

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
constexpr ushort kCursorLeftMarker = 0xE002;
constexpr ushort kCursorRightMarker = 0xE003;
constexpr ushort kCursorUpMarker = 0xE004;
constexpr ushort kCursorDownMarker = 0xE005;
constexpr ushort kEraseDisplayBelowMarker = 0xE006;
constexpr ushort kEraseDisplayAboveMarker = 0xE007;
constexpr ushort kEraseDisplayAllMarker = 0xE008;
constexpr ushort kClearLineLeftMarker = 0xE009;
constexpr ushort kSaveCursorMarker = 0xE00A;
constexpr ushort kRestoreCursorMarker = 0xE00B;
constexpr ushort kSetAbsoluteColumnMarker = 0xE00C;
constexpr ushort kSetAbsoluteRowMarker = 0xE00D;
constexpr ushort kSetAbsolutePositionMarker = 0xE00E;
constexpr ushort kEnterAltScreenMarker = 0xE00F;
constexpr ushort kExitAltScreenMarker = 0xE010;
constexpr ushort kMarkerValueBase = 0xE100;
constexpr ushort kMarkerValueMax = 0xE1FF;
constexpr int kMaxTerminalLines = 3000;
const QChar kTerminalCursorMarker(0x258F);

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

QChar encodeMarkerValue(int value) {
  return QChar(static_cast<ushort>(
      kMarkerValueBase + std::clamp(value, 0, static_cast<int>(kMarkerValueMax - kMarkerValueBase))));
}

bool isMarkerValue(QChar ch) {
  const auto code = ch.unicode();
  return code >= kMarkerValueBase && code <= kMarkerValueMax;
}

int decodeMarkerValue(QChar ch, int fallback) {
  return isMarkerValue(ch) ? static_cast<int>(ch.unicode() - kMarkerValueBase) : fallback;
}

QStringList splitCsiParams(const QString& sequence) {
  QString payload = sequence.trimmed();
  if (payload.startsWith(QChar::fromLatin1('?'))) {
    payload.remove(0, 1);
  }
  return payload.split(QChar::fromLatin1(';'), Qt::KeepEmptyParts);
}

int csiParamValue(const QStringList& params, int index, int default_value) {
  if (index < 0 || index >= params.size() || params.at(index).trimmed().isEmpty()) {
    return default_value;
  }
  bool ok = false;
  const int value = params.at(index).trimmed().toInt(&ok);
  return ok ? value : default_value;
}

int csiCountOrOne(const QString& sequence) {
  const auto params = splitCsiParams(sequence);
  const int value = csiParamValue(params, 0, 1);
  return value <= 0 ? 1 : value;
}

bool stderrIndicatesTransientNetworkFailure(const QString& text) {
  const auto lower = text.toLower();
  return lower.contains(QStringLiteral("no route to host")) ||
         lower.contains(QStringLiteral("network is unreachable")) ||
         lower.contains(QStringLiteral("connection timed out"));
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
  QString filtered;
  filtered.reserve(text.size());
  for (const auto ch : text) {
    const auto code = ch.unicode();
    if (code >= kClearLineRightMarker && code <= kExitAltScreenMarker) {
      continue;
    }
    if (code >= kMarkerValueBase && code <= kMarkerValueMax) {
      continue;
    }
    filtered.append(ch);
  }
  return filtered;
}

QString jsSingleArgument(const QString& value) {
  QJsonArray array;
  array.push_back(value);
  const auto json = QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
  return json.mid(1, json.size() - 2);
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
    setLineWrapMode(QPlainTextEdit::WidgetWidth);
    setWordWrapMode(QTextOption::WrapAnywhere);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setFocusPolicy(Qt::StrongFocus);
    setTabChangesFocus(false);
    setCursorWidth(0);
  }

  void setInputHandler(std::function<void(QByteArray)> handler) {
    input_handler_ = std::move(handler);
  }

  void setResizeHandler(std::function<void()> handler) {
    resize_handler_ = std::move(handler);
  }

 protected:
  void keyPressEvent(QKeyEvent* event) override {
    const auto modifiers = event->modifiers();

#if defined(Q_OS_MACOS)
    // Qt swaps Command/Control semantics on macOS by default:
    // ControlModifier -> Command key, MetaModifier -> physical Control key.
    const bool physical_ctrl_only =
        (modifiers & Qt::MetaModifier) && !(modifiers & Qt::AltModifier) &&
        !(modifiers & Qt::ControlModifier) && !(modifiers & Qt::ShiftModifier);
    const bool command_only =
        (modifiers & Qt::ControlModifier) && !(modifiers & Qt::AltModifier) &&
        !(modifiers & Qt::MetaModifier) && !(modifiers & Qt::ShiftModifier);
#else
    const bool physical_ctrl_only =
        (modifiers & Qt::ControlModifier) && !(modifiers & Qt::AltModifier) &&
        !(modifiers & Qt::MetaModifier) && !(modifiers & Qt::ShiftModifier);
    const bool command_only = false;
#endif

    const bool terminal_copy_shortcut =
#if defined(Q_OS_MACOS)
        command_only && event->key() == Qt::Key_C;
#else
        ((modifiers & Qt::ControlModifier) &&
         (modifiers & Qt::ShiftModifier) && event->key() == Qt::Key_C);
#endif
    const bool terminal_paste_shortcut =
#if defined(Q_OS_MACOS)
        command_only && event->key() == Qt::Key_V;
#else
        ((modifiers & Qt::ControlModifier) &&
         (modifiers & Qt::ShiftModifier) && event->key() == Qt::Key_V);
#endif

    if (physical_ctrl_only) {
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

    if (terminal_copy_shortcut) {
      copy();
      return;
    }

    if (terminal_paste_shortcut) {
      const auto* clipboard = QGuiApplication::clipboard();
      if (clipboard != nullptr) {
        sendData(clipboard->text().toUtf8());
      }
      return;
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

    event->ignore();
  }

  void resizeEvent(QResizeEvent* event) override {
    QPlainTextEdit::resizeEvent(event);
    if (resize_handler_) {
      resize_handler_();
    }
  }

  bool focusNextPrevChild(bool) override {
    return false;
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

#if defined(GMSSH_HAS_WEBTERMINAL)
class WebTerminalBridge final : public QObject {
  Q_OBJECT

 public:
  explicit WebTerminalBridge(QObject* parent = nullptr) : QObject(parent) {}

 signals:
  void inputData(const QByteArray& data);
  void terminalResized(int cols, int rows);
  void frontendReady();

 public slots:
  void sendInputBase64(const QString& payload) {
    const auto decoded = QByteArray::fromBase64(payload.toUtf8(), QByteArray::Base64Encoding);
    if (!decoded.isEmpty()) {
      emit inputData(decoded);
    }
  }

  void resizeTerminal(int cols, int rows) {
    emit terminalResized(cols, rows);
  }

  void notifyReady() {
    emit frontendReady();
  }
};
#endif

}  // namespace

TerminalSessionWidget::TerminalSessionWidget(
    QString session_name,
    ConnectionProfile profile,
    SessionSecrets secrets,
    SshLaunchPlan launch_plan,
    AuditLogger* audit_logger,
    SshEngineAdapter* engine_adapter,
    QWidget* parent)
    : QWidget(parent),
      session_name_(std::move(session_name)),
      session_audit_id_(QUuid::createUuid().toString(QUuid::WithoutBraces)),
      profile_(std::move(profile)),
      secrets_(std::move(secrets)),
      launch_plan_(std::move(launch_plan)),
      audit_logger_(audit_logger),
      engine_adapter_(engine_adapter) {
  terminal_lines_.push_back(QString());

  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(6, 6, 6, 6);
  layout->setSpacing(8);

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

  auto* terminal_view = new TerminalOutputView(this);
  output_view_ = terminal_view;
  output_view_->setObjectName(QStringLiteral("terminalOutputView"));
  output_view_->setMinimumHeight(240);
  output_view_->setFont(terminal_font);
  terminal_view->setInputHandler([this](const QByteArray& data) {
    writeTerminalInput(data);
  });
  terminal_view->setResizeHandler([this]() {
    updateTerminalWindowSize();
  });
  connect(
      output_view_->verticalScrollBar(),
      &QScrollBar::valueChanged,
      this,
      [this](int value) {
        if (output_view_ == nullptr || suppress_scroll_tracking_) {
          return;
        }
        auto* scroll_bar = output_view_->verticalScrollBar();
        follow_output_tail_ = value >= scroll_bar->maximum();
      });
  render_coalesce_timer_ = new QTimer(this);
  render_coalesce_timer_->setSingleShot(true);
  render_coalesce_timer_->setInterval(16);
  connect(render_coalesce_timer_, &QTimer::timeout, this, [this]() {
    if (!render_pending_) {
      return;
    }
    render_pending_ = false;
    renderTerminalBuffer();
  });
#if defined(GMSSH_HAS_WEBTERMINAL)
  use_web_terminal_ = true;
  web_terminal_view_ = new QWebEngineView(this);
  web_terminal_view_->setObjectName(QStringLiteral("terminalWebView"));
  web_terminal_view_->setMinimumHeight(240);
  web_terminal_view_->setFocusPolicy(Qt::StrongFocus);
  web_terminal_view_->settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
  web_terminal_view_->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true);
  web_terminal_view_->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
  layout->addWidget(web_terminal_view_, 1);

  output_view_->hide();

  web_channel_ = new QWebChannel(web_terminal_view_->page());
  auto* bridge = new WebTerminalBridge(this);
  web_terminal_bridge_ = bridge;
  web_channel_->registerObject(QStringLiteral("bridge"), bridge);
  web_terminal_view_->page()->setWebChannel(web_channel_);
  connect(bridge, &WebTerminalBridge::inputData, this, [this](const QByteArray& data) {
    writeTerminalInput(data);
  });
  connect(bridge, &WebTerminalBridge::terminalResized, this, [this](int cols, int rows) {
    terminal_cols_ = std::max(20, cols);
    terminal_rows_ = std::max(6, rows);
    updateTerminalWindowSize();
  });
  connect(bridge, &WebTerminalBridge::frontendReady, this, [this]() {
    if (!use_web_terminal_) {
      return;
    }
    web_terminal_ready_ = true;
    if (web_terminal_bootstrap_timer_ != nullptr) {
      web_terminal_bootstrap_timer_->stop();
    }
    if (web_terminal_view_ == nullptr) {
      return;
    }
    for (const auto& payload : pending_web_output_) {
      const auto script = QStringLiteral("window.gmsshWriteBase64(%1);")
                              .arg(jsSingleArgument(payload));
      web_terminal_view_->page()->runJavaScript(script);
    }
    pending_web_output_.clear();
    if (launch_plan_.ok && (pty_master_fd_ < 0 && terminal_process_ == nullptr)) {
      startTerminalProcess();
    }
  });
  connect(web_terminal_view_, &QWebEngineView::loadFinished, this, [this](bool ok) {
    handleWebTerminalLoadFinished(ok);
  });
  connect(
      web_terminal_view_->page(),
      &QWebEnginePage::loadingChanged,
      this,
      [this](const QWebEngineLoadingInfo& info) {
        if (info.status() == QWebEngineLoadingInfo::LoadFailedStatus) {
          logAuditEvent(
              QStringLiteral("web_terminal_loading_failed_detail"),
              QJsonObject{
                  {QStringLiteral("attempt"), web_terminal_bootstrap_attempt_},
                  {QStringLiteral("url"), info.url().toString()},
                  {QStringLiteral("error_domain"), static_cast<int>(info.errorDomain())},
                  {QStringLiteral("error_code"), info.errorCode()},
                  {QStringLiteral("error_string"), info.errorString()}});
        }
      });
  connect(
      web_terminal_view_,
      &QWebEngineView::renderProcessTerminated,
      this,
      [this](QWebEnginePage::RenderProcessTerminationStatus status, int exit_code) {
        logAuditEvent(
            QStringLiteral("web_terminal_render_process_terminated"),
            QJsonObject{{QStringLiteral("attempt"), web_terminal_bootstrap_attempt_},
                        {QStringLiteral("status"), static_cast<int>(status)},
                        {QStringLiteral("exit_code"), exit_code}});
      });

  web_terminal_bootstrap_timer_ = new QTimer(this);
  web_terminal_bootstrap_timer_->setSingleShot(true);
  web_terminal_bootstrap_timer_->setInterval(12000);
  connect(web_terminal_bootstrap_timer_, &QTimer::timeout, this, [this]() {
    handleWebTerminalBootstrapTimeout();
  });

  beginWebTerminalBootstrap();
#else
  layout->addWidget(output_view_, 1);
#endif

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
#if defined(GMSSH_HAS_WEBTERMINAL)
  if (!use_web_terminal_ || web_terminal_ready_) {
    startTerminalProcess();
  }
#else
  startTerminalProcess();
#endif
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

QString TerminalSessionWidget::terminalText() const {
#if defined(GMSSH_HAS_WEBTERMINAL)
  if (use_web_terminal_) {
    return terminal_transcript_;
  }
#endif
  return output_view_ != nullptr ? output_view_->toPlainText() : QString();
}

void TerminalSessionWidget::requestClearScreen() {
  writeTerminalInput(QByteArray(1, 0x0c));
}

void TerminalSessionWidget::activateInputFocus() {
#if defined(GMSSH_HAS_WEBTERMINAL)
  if (use_web_terminal_ && web_terminal_view_ != nullptr) {
    web_terminal_view_->setFocus();
    return;
  }
#endif
  if (output_view_ == nullptr) {
    return;
  }
  follow_output_tail_ = true;
  scrollToBottom();
  output_view_->setFocus();
}

#if defined(GMSSH_HAS_WEBTERMINAL)
void TerminalSessionWidget::beginWebTerminalBootstrap() {
  if (!use_web_terminal_ || web_terminal_view_ == nullptr) {
    return;
  }
  web_terminal_ready_ = false;
  web_terminal_bootstrap_attempt_ = 1;
  scheduleWebTerminalBootstrapTimeout();
  const QUrl terminal_base_url(QStringLiteral("qrc:///terminal/"));
  QFile terminal_html_file(QStringLiteral(":/terminal/terminal.html"));
  if (terminal_html_file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    web_terminal_view_->setHtml(QString::fromUtf8(terminal_html_file.readAll()), terminal_base_url);
  } else {
    web_terminal_view_->setUrl(QUrl(QStringLiteral("qrc:///terminal/terminal.html")));
  }
}

void TerminalSessionWidget::scheduleWebTerminalBootstrapTimeout() {
  if (web_terminal_bootstrap_timer_ == nullptr) {
    return;
  }
  web_terminal_bootstrap_timer_->stop();
  web_terminal_bootstrap_timer_->start();
}

void TerminalSessionWidget::handleWebTerminalLoadFinished(bool ok) {
  if (!use_web_terminal_) {
    return;
  }
  if (ok) {
    return;
  }
  logAuditEvent(
      QStringLiteral("web_terminal_load_failed"),
      QJsonObject{
          {QStringLiteral("attempt"), web_terminal_bootstrap_attempt_},
          {QStringLiteral("url"),
           web_terminal_view_ != nullptr ? web_terminal_view_->url().toString() : QString()}});
}

void TerminalSessionWidget::handleWebTerminalBootstrapTimeout() {
  if (!use_web_terminal_ || web_terminal_ready_) {
    return;
  }
  failWebTerminalBootstrap(QStringLiteral("Web 终端初始化超时或资源加载失败"));
}

void TerminalSessionWidget::failWebTerminalBootstrap(const QString& reason) {
  web_terminal_ready_ = false;
  pending_web_output_.clear();
  if (web_terminal_bootstrap_timer_ != nullptr) {
    web_terminal_bootstrap_timer_->stop();
  }

  const QString detail = reason.isEmpty() ? QStringLiteral("未知原因") : reason;
  terminal_transcript_.append(
      QStringLiteral("[错误] %1。请关闭当前标签后重新连接。\n").arg(detail));
  auditTerminalOutput(QStringLiteral("[错误] %1\n").arg(detail));
  logAuditEvent(
      QStringLiteral("web_terminal_bootstrap_failed"),
      QJsonObject{{QStringLiteral("reason"), detail},
                  {QStringLiteral("attempt"), web_terminal_bootstrap_attempt_}});

  if (web_terminal_view_ != nullptr) {
    const QString error_html = QStringLiteral(
                                   "<!doctype html><html><head><meta charset=\"utf-8\"/>"
                                   "<style>"
                                   "html,body{margin:0;height:100%;background:#f8fafc;color:#0f172a;"
                                   "font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',"
                                   "'PingFang SC','Microsoft YaHei',sans-serif;}"
                                   ".wrap{height:100%;display:flex;align-items:center;justify-content:center;"
                                   "padding:24px;box-sizing:border-box;}"
                                   ".card{max-width:560px;padding:20px 22px;border:1px solid #cbd5e1;"
                                   "border-radius:12px;background:#ffffff;box-shadow:0 8px 24px rgba(15,23,42,0.08);}"
                                   ".title{font-size:16px;font-weight:700;margin:0 0 8px 0;}"
                                   ".desc{font-size:13px;line-height:1.6;color:#334155;margin:0;}"
                                   "</style></head><body><div class=\"wrap\"><div class=\"card\">"
                                   "<p class=\"title\">Web 终端启动失败</p>"
                                   "<p class=\"desc\">原因：%1<br/>请关闭当前会话标签后重新连接。"
                                   "如果问题持续，请反馈当前系统和 Qt 运行环境信息。</p>"
                                   "</div></div></body></html>")
                                   .arg(detail.toHtmlEscaped());
    web_terminal_view_->setHtml(error_html, QUrl(QStringLiteral("about:blank")));
    web_terminal_view_->setFocus();
  }
}
#endif

void TerminalSessionWidget::appendOutput(const QString& text) {
  if (text.isEmpty()) {
    return;
  }

#if defined(GMSSH_HAS_WEBTERMINAL)
  if (use_web_terminal_) {
    const auto audited = sanitizeTerminalOutput(text);
    if (!audited.isEmpty()) {
      terminal_transcript_.append(audited);
      if (looksLikeSensitivePrompt(audited)) {
        sensitive_input_active_ = true;
      }
      auditTerminalOutput(audited);
    }

    const auto append_web_text = [this](const QString& chunk) {
      if (chunk.isEmpty()) {
        return;
      }
      const auto payload = QString::fromUtf8(chunk.toUtf8().toBase64());
      if (!web_terminal_ready_ || web_terminal_view_ == nullptr) {
        pending_web_output_.push_back(payload);
        return;
      }
      const auto script = QStringLiteral("window.gmsshWriteBase64(%1);").arg(jsSingleArgument(payload));
      web_terminal_view_->page()->runJavaScript(script);
    };

    const auto display_text = displaySafeDiagnostics(text);
    if (!launch_plan_.gm_hostsig_compatibility_bypass &&
        text.contains(
            QStringLiteral("host signature verify bypass enabled for compatibility"),
            Qt::CaseInsensitive)) {
      append_web_text(display_text);
      append_web_text(
          QStringLiteral(
              "\n[错误] 严格模式已阻断旧版国密主机签名适配，请在“安全”菜单切换为“国密旧版服务端适配（降低校验强度）”后重试。\n"));
      closeTerminalProcess();
      finishTerminalSession(-1, false);
      return;
    }
    if (!launch_plan_.gm_hostsig_compatibility_bypass &&
        text.contains(
            QStringLiteral("legacy GM host-signature adaptation enabled"),
            Qt::CaseInsensitive)) {
      append_web_text(display_text);
      append_web_text(
          QStringLiteral(
              "\n[错误] 严格模式已阻断旧版国密主机签名适配，请在“安全”菜单切换为“国密旧版服务端适配（降低校验强度）”后重试。\n"));
      closeTerminalProcess();
      finishTerminalSession(-1, false);
      return;
    }
    append_web_text(display_text);
    return;
  }
#endif

  const auto sanitized = sanitizeTerminalOutput(text);
  if (sanitized.isEmpty()) {
    return;
  }
  terminal_transcript_.append(sanitized);

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

  bool saw_screen_repaint_control = false;
  bool entered_alt_screen = false;
  bool exited_alt_screen = false;

  for (int i = 0; i < text.size(); ++i) {
    const auto ch = text.at(i);
    if (ch.unicode() == kEnterAltScreenMarker) {
      in_alternate_screen_ = true;
      in_screen_repaint_mode_ = true;
      non_repaint_chunks_in_screen_mode_ = 0;
      entered_alt_screen = true;
      terminal_lines_.clear();
      terminal_lines_.push_back(QString());
      cursor_row_ = 0;
      cursor_col_ = 0;
      continue;
    }
    if (ch.unicode() == kExitAltScreenMarker) {
      in_alternate_screen_ = false;
      in_screen_repaint_mode_ = false;
      non_repaint_chunks_in_screen_mode_ = 0;
      exited_alt_screen = true;
      continue;
    }
    if (ch.unicode() == kClearLineRightMarker) {
      clearCurrentLineRight();
      continue;
    }
    if (ch.unicode() == kClearWholeLineMarker) {
      applyEraseInLine(2);
      continue;
    }
    if (ch.unicode() == kClearLineLeftMarker) {
      applyEraseInLine(1);
      continue;
    }
    if (ch.unicode() == kCursorLeftMarker) {
      cursor_col_ = std::max(0, cursor_col_ - 1);
      continue;
    }
    if (ch.unicode() == kCursorRightMarker) {
      cursor_col_ = std::max(0, cursor_col_ + 1);
      continue;
    }
    if (ch.unicode() == kCursorUpMarker) {
      saw_screen_repaint_control = true;
      cursor_row_ = std::max(0, cursor_row_ - 1);
      ensureCursorRowExists(cursor_row_);
      continue;
    }
    if (ch.unicode() == kCursorDownMarker) {
      saw_screen_repaint_control = true;
      moveCursorToRowCol(cursor_row_ + 1, cursor_col_);
      continue;
    }
    if (ch.unicode() == kEraseDisplayBelowMarker) {
      saw_screen_repaint_control = true;
      applyEraseInDisplay(0);
      continue;
    }
    if (ch.unicode() == kEraseDisplayAboveMarker) {
      saw_screen_repaint_control = true;
      applyEraseInDisplay(1);
      continue;
    }
    if (ch.unicode() == kEraseDisplayAllMarker) {
      saw_screen_repaint_control = true;
      applyEraseInDisplay(2);
      continue;
    }
    if (ch.unicode() == kSaveCursorMarker) {
      saved_cursor_row_ = cursor_row_;
      saved_cursor_col_ = cursor_col_;
      has_saved_cursor_ = true;
      continue;
    }
    if (ch.unicode() == kRestoreCursorMarker) {
      if (has_saved_cursor_) {
        moveCursorToRowCol(saved_cursor_row_, saved_cursor_col_);
      }
      continue;
    }
    if (ch.unicode() == kSetAbsoluteColumnMarker) {
      if (i + 1 < text.size()) {
        cursor_col_ = std::max(0, decodeMarkerValue(text.at(i + 1), cursor_col_) - 1);
        ++i;
      }
      continue;
    }
    if (ch.unicode() == kSetAbsoluteRowMarker) {
      saw_screen_repaint_control = true;
      if (i + 1 < text.size()) {
        const int target_row = std::max(0, decodeMarkerValue(text.at(i + 1), cursor_row_ + 1) - 1);
        moveCursorToRowCol(target_row, cursor_col_);
        ++i;
      }
      continue;
    }
    if (ch.unicode() == kSetAbsolutePositionMarker) {
      saw_screen_repaint_control = true;
      if (i + 2 < text.size()) {
        const int target_row = std::max(0, decodeMarkerValue(text.at(i + 1), cursor_row_ + 1) - 1);
        const int target_col = std::max(0, decodeMarkerValue(text.at(i + 2), cursor_col_ + 1) - 1);
        moveCursorToRowCol(target_row, target_col);
        i += 2;
      }
      continue;
    }
    if ((ch.unicode() >= kClearLineRightMarker && ch.unicode() <= kExitAltScreenMarker) ||
        (ch.unicode() >= kMarkerValueBase && ch.unicode() <= kMarkerValueMax)) {
      continue;
    }
    if (ch == QChar::fromLatin1('\r')) {
      cursor_col_ = 0;
      continue;
    }
    if (ch == QChar::fromLatin1('\n')) {
      if ((in_alternate_screen_ || in_screen_repaint_mode_) && terminal_rows_ > 0) {
        cursor_col_ = 0;
        if (cursor_row_ >= terminal_rows_ - 1) {
          trimToTerminalViewportRows();
          if (terminal_lines_.isEmpty()) {
            terminal_lines_.push_back(QString());
          } else {
            terminal_lines_.removeFirst();
          }
          terminal_lines_.push_back(QString());
          cursor_row_ = std::max(0, terminal_rows_ - 1);
          if (has_saved_cursor_) {
            saved_cursor_row_ = std::max(0, saved_cursor_row_ - 1);
          }
        } else {
          moveCursorToRowCol(cursor_row_ + 1, 0);
        }
      } else {
        moveCursorToRowCol(cursor_row_ + 1, 0);
      }
      continue;
    }
    putTerminalChar(ch);
  }

  if (entered_alt_screen || saw_screen_repaint_control) {
    in_screen_repaint_mode_ = true;
    non_repaint_chunks_in_screen_mode_ = 0;
  } else if (!in_alternate_screen_ && in_screen_repaint_mode_) {
    ++non_repaint_chunks_in_screen_mode_;
    if (non_repaint_chunks_in_screen_mode_ >= 12) {
      in_screen_repaint_mode_ = false;
      non_repaint_chunks_in_screen_mode_ = 0;
    }
  }

  follow_output_tail_ = !in_alternate_screen_ && !in_screen_repaint_mode_;
  if (in_alternate_screen_ || in_screen_repaint_mode_) {
    trimToTerminalViewportRows();
  }
  if (exited_alt_screen) {
    follow_output_tail_ = true;
  }
  const bool should_coalesce_render = in_alternate_screen_ || in_screen_repaint_mode_;
  if (should_coalesce_render && render_coalesce_timer_ != nullptr) {
    render_pending_ = true;
    if (!render_coalesce_timer_->isActive()) {
      render_coalesce_timer_->start();
    }
    return;
  }
  if (render_coalesce_timer_ != nullptr && render_coalesce_timer_->isActive()) {
    render_coalesce_timer_->stop();
  }
  render_pending_ = false;
  renderTerminalBuffer();
}

void TerminalSessionWidget::renderTerminalBuffer() {
  const int line_limit =
      (in_alternate_screen_ || in_screen_repaint_mode_) && terminal_rows_ > 0
          ? terminal_rows_
          : kMaxTerminalLines;
  while (terminal_lines_.size() > line_limit) {
    terminal_lines_.removeFirst();
    cursor_row_ = std::max(0, cursor_row_ - 1);
    if (has_saved_cursor_) {
      saved_cursor_row_ = std::max(0, saved_cursor_row_ - 1);
    }
  }

  const bool should_follow = follow_output_tail_;
  const int previous_scroll_value =
      output_view_ != nullptr ? output_view_->verticalScrollBar()->value() : 0;
  suppress_scroll_tracking_ = true;
  QStringList display_lines = terminal_lines_;
  if (display_lines.isEmpty()) {
    display_lines.push_back(QString());
  }
  const int display_row =
      std::clamp(cursor_row_, 0, static_cast<int>(display_lines.size()) - 1);
  auto& line = display_lines[display_row];
  const int display_col = std::clamp(cursor_col_, 0, static_cast<int>(line.size()));
  line.insert(display_col, kTerminalCursorMarker);

  output_view_->setPlainText(display_lines.join(QChar::fromLatin1('\n')));
  if (should_follow) {
    scrollToBottom();
  } else if (in_alternate_screen_ || in_screen_repaint_mode_) {
    scrollToCursor();
  } else {
    output_view_->verticalScrollBar()->setValue(previous_scroll_value);
  }
  follow_output_tail_ = should_follow;
  suppress_scroll_tracking_ = false;
}

void TerminalSessionWidget::putTerminalChar(QChar ch) {
  if (terminal_lines_.isEmpty()) {
    terminal_lines_.push_back(QString());
  }
  cursor_row_ = std::clamp(cursor_row_, 0, static_cast<int>(terminal_lines_.size()) - 1);

  if (ch == QChar::fromLatin1('\b') || ch.unicode() == 0x7f) {
    if (cursor_col_ > 0) {
      --cursor_col_;
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
    // Terminal output writes to the current cell and replaces existing content.
    // Using insert() here desynchronizes line-edit redraw from readline/zle.
    line[cursor_col_] = ch;
  } else {
    line.append(ch);
  }
  ++cursor_col_;
}

void TerminalSessionWidget::ensureCursorRowExists(int row) {
  if (terminal_lines_.isEmpty()) {
    terminal_lines_.push_back(QString());
  }
  if (row < 0) {
    cursor_row_ = 0;
    return;
  }
  while (row >= terminal_lines_.size()) {
    terminal_lines_.push_back(QString());
  }
  cursor_row_ = std::clamp(row, 0, static_cast<int>(terminal_lines_.size()) - 1);
}

void TerminalSessionWidget::moveCursorToRowCol(int row, int col) {
  int target_row = std::max(0, row);
  if ((in_alternate_screen_ || in_screen_repaint_mode_) && terminal_rows_ > 0) {
    target_row = std::min(target_row, terminal_rows_ - 1);
  }
  ensureCursorRowExists(target_row);
  cursor_col_ = std::max(0, col);
}

void TerminalSessionWidget::clearCurrentLineRight() {
  if (terminal_lines_.isEmpty()) {
    return;
  }
  ensureCursorRowExists(cursor_row_);
  auto& line = terminal_lines_[cursor_row_];
  if (cursor_col_ < line.size()) {
    line.truncate(cursor_col_);
  }
}

void TerminalSessionWidget::applyEraseInDisplay(int mode) {
  ensureCursorRowExists(cursor_row_);
  if (mode == 2) {
    terminal_lines_.clear();
    terminal_lines_.push_back(QString());
    cursor_row_ = 0;
    cursor_col_ = 0;
    return;
  }

  if (mode == 1) {
    for (int i = 0; i < cursor_row_; ++i) {
      terminal_lines_[i].clear();
    }
    auto& line = terminal_lines_[cursor_row_];
    const int boundary = std::min(cursor_col_, static_cast<int>(line.size()));
    for (int i = 0; i < boundary; ++i) {
      line[i] = QChar::fromLatin1(' ');
    }
    return;
  }

  clearCurrentLineRight();
  while (terminal_lines_.size() > cursor_row_ + 1) {
    terminal_lines_.removeLast();
  }
}

void TerminalSessionWidget::applyEraseInLine(int mode) {
  ensureCursorRowExists(cursor_row_);
  auto& line = terminal_lines_[cursor_row_];
  if (mode == 2) {
    line.clear();
    return;
  }

  if (mode == 1) {
    if (line.size() < cursor_col_) {
      line.append(QString(cursor_col_ - line.size(), QChar::fromLatin1(' ')));
    }
    const int boundary = std::min(cursor_col_, static_cast<int>(line.size()));
    for (int i = 0; i < boundary; ++i) {
      line[i] = QChar::fromLatin1(' ');
    }
    return;
  }

  clearCurrentLineRight();
}

void TerminalSessionWidget::trimToTerminalViewportRows() {
  if (terminal_rows_ <= 0) {
    return;
  }
  while (terminal_lines_.size() > terminal_rows_) {
    terminal_lines_.removeFirst();
    cursor_row_ = std::max(0, cursor_row_ - 1);
    if (has_saved_cursor_) {
      saved_cursor_row_ = std::max(0, saved_cursor_row_ - 1);
    }
  }
}

void TerminalSessionWidget::scrollToCursor() {
  if (output_view_ == nullptr) {
    return;
  }
  auto cursor = output_view_->textCursor();
  cursor.movePosition(QTextCursor::Start);
  const int target_row = std::max(0, cursor_row_);
  for (int row = 0; row < target_row; ++row) {
    cursor.movePosition(QTextCursor::Down);
  }
  cursor.movePosition(QTextCursor::StartOfLine);
  output_view_->setTextCursor(cursor);
  output_view_->ensureCursorVisible();
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
        if (ch == QChar::fromLatin1('(') || ch == QChar::fromLatin1(')') ||
            ch == QChar::fromLatin1('*') || ch == QChar::fromLatin1('+') ||
            ch == QChar::fromLatin1('-') || ch == QChar::fromLatin1('.') ||
            ch == QChar::fromLatin1('/')) {
          // e.g. ESC(B charset designator; swallow the final byte too.
          escape_parse_state_ = EscapeParseState::EscapeCharset;
          continue;
        }
        if (ch == QChar::fromLatin1('7')) {
          cleaned.append(QChar(kSaveCursorMarker));
          escape_parse_state_ = EscapeParseState::Text;
          continue;
        }
        if (ch == QChar::fromLatin1('8')) {
          cleaned.append(QChar(kRestoreCursorMarker));
          escape_parse_state_ = EscapeParseState::Text;
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

      case EscapeParseState::EscapeCharset:
        escape_parse_state_ = EscapeParseState::Text;
        continue;

      case EscapeParseState::Csi:
        if (code >= 0x40 && code <= 0x7E) {
          const auto trimmed_sequence = csi_sequence_.trimmed();
          const bool private_mode = trimmed_sequence.startsWith(QChar::fromLatin1('?'));
          const auto params = splitCsiParams(csi_sequence_);

          if (ch == QChar::fromLatin1('K')) {
            const int mode = csiParamValue(params, 0, 0);
            if (mode == 2) {
              cleaned.append(QChar(kClearWholeLineMarker));
            } else if (mode == 1) {
              cleaned.append(QChar(kClearLineLeftMarker));
            } else {
              cleaned.append(QChar(kClearLineRightMarker));
            }
          } else if (ch == QChar::fromLatin1('J')) {
            const int mode = csiParamValue(params, 0, 0);
            if (mode == 1) {
              cleaned.append(QChar(kEraseDisplayAboveMarker));
            } else if (mode == 2 || mode == 3) {
              cleaned.append(QChar(kEraseDisplayAllMarker));
            } else {
              cleaned.append(QChar(kEraseDisplayBelowMarker));
            }
          } else if (ch == QChar::fromLatin1('D')) {
            const int count = csiCountOrOne(csi_sequence_);
            for (int i = 0; i < count; ++i) {
              cleaned.append(QChar(kCursorLeftMarker));
            }
          } else if (ch == QChar::fromLatin1('C')) {
            const int count = csiCountOrOne(csi_sequence_);
            for (int i = 0; i < count; ++i) {
              cleaned.append(QChar(kCursorRightMarker));
            }
          } else if (ch == QChar::fromLatin1('A')) {
            const int count = csiCountOrOne(csi_sequence_);
            for (int i = 0; i < count; ++i) {
              cleaned.append(QChar(kCursorUpMarker));
            }
          } else if (ch == QChar::fromLatin1('B')) {
            const int count = csiCountOrOne(csi_sequence_);
            for (int i = 0; i < count; ++i) {
              cleaned.append(QChar(kCursorDownMarker));
            }
          } else if (ch == QChar::fromLatin1('G')) {
            const int col = std::max(1, csiParamValue(params, 0, 1));
            cleaned.append(QChar(kSetAbsoluteColumnMarker));
            cleaned.append(encodeMarkerValue(col));
          } else if (ch == QChar::fromLatin1('d')) {
            const int row = std::max(1, csiParamValue(params, 0, 1));
            cleaned.append(QChar(kSetAbsoluteRowMarker));
            cleaned.append(encodeMarkerValue(row));
          } else if (ch == QChar::fromLatin1('H') || ch == QChar::fromLatin1('f')) {
            const int row = std::max(1, csiParamValue(params, 0, 1));
            const int col = std::max(1, csiParamValue(params, 1, 1));
            cleaned.append(QChar(kSetAbsolutePositionMarker));
            cleaned.append(encodeMarkerValue(row));
            cleaned.append(encodeMarkerValue(col));
          } else if (ch == QChar::fromLatin1('s')) {
            cleaned.append(QChar(kSaveCursorMarker));
          } else if (ch == QChar::fromLatin1('u')) {
            cleaned.append(QChar(kRestoreCursorMarker));
          } else if (private_mode &&
                     (ch == QChar::fromLatin1('h') || ch == QChar::fromLatin1('l'))) {
            const int mode = csiParamValue(params, 0, 0);
            if (mode == 47 || mode == 1047 || mode == 1049) {
              if (ch == QChar::fromLatin1('h')) {
                cleaned.append(QChar(kEnterAltScreenMarker));
              } else {
                cleaned.append(QChar(kExitAltScreenMarker));
              }
            }
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

  if (output_view_ != nullptr) {
    const QFontMetrics metrics(output_view_->font());
    terminal_cols_ = std::max(
        20, output_view_->viewport()->width() /
                std::max(1, metrics.horizontalAdvance(QChar::fromLatin1('M'))));
    terminal_rows_ =
        std::max(6, output_view_->viewport()->height() / std::max(1, metrics.lineSpacing()));
  } else {
    terminal_cols_ = std::max(20, terminal_cols_);
    terminal_rows_ = std::max(6, terminal_rows_);
  }
  struct winsize window_size {};
  window_size.ws_col = static_cast<unsigned short>(terminal_cols_);
  window_size.ws_row = static_cast<unsigned short>(terminal_rows_);

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
  activateInputFocus();

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
    activateInputFocus();
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
  follow_output_tail_ = true;
  if (!data.isEmpty()) {
    user_input_detected_ = true;
  }
  if (output_view_ != nullptr) {
    scrollToBottom();
    output_view_->setFocus();
  }
#if defined(GMSSH_HAS_WEBTERMINAL)
  if (use_web_terminal_ && web_terminal_view_ != nullptr) {
    web_terminal_view_->setFocus();
  }
#endif
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

  if (shouldAutoRetryTransientNetworkFailure(exit_code)) {
    retry_attempted_ = true;
    appendOutput(QStringLiteral("\n[系统] 检测到瞬时网络错误，正在自动重试一次...\n"));
    logAuditEvent(
        QStringLiteral("session_retry"),
        QJsonObject{{QStringLiteral("reason"), QStringLiteral("transient_network_failure")}});
    bool retry_ready = true;
    if (engine_adapter_ != nullptr) {
      const auto refreshed_plan = engine_adapter_->prepareLaunch(profile_, secrets_);
      if (!refreshed_plan.ok) {
        appendOutput(
            QStringLiteral("[错误] 自动重试准备失败：%1\n").arg(refreshed_plan.error));
        retry_ready = false;
      } else {
        launch_plan_ = refreshed_plan;
        appendOutput(QStringLiteral("[系统] 自动重试已刷新连接参数。\n"));
        appendOutput(QStringLiteral("[系统] 当前 SSH 引擎：%1\n").arg(launch_plan_.program));
        appendOutput(
            QStringLiteral("[系统] 连接方式：%1\n")
                .arg(selectedModeZh(launch_plan_.selected_mode)));
        appendOutput(
            QStringLiteral("[系统] 国密主机签名校验：%1\n")
                .arg(launch_plan_.gm_hostsig_compatibility_bypass
                         ? QStringLiteral("旧版国密适配（降低校验强度）")
                         : QStringLiteral("严格校验（推荐）")));
        if (launch_plan_.engine_fallback_used) {
          appendOutput(
              QStringLiteral("[系统] 已自动切换 SSH 引擎：\n  from: %1\n  to:   %2\n  reason: %3\n")
                  .arg(launch_plan_.engine_fallback_from,
                       launch_plan_.engine_fallback_to,
                       engineFallbackReasonZh(launch_plan_.engine_fallback_reason)));
        }
      }
    }
    if (retry_ready) {
      QTimer::singleShot(800, this, [this]() {
        startTerminalProcess();
      });
      return;
    }
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

bool TerminalSessionWidget::shouldAutoRetryTransientNetworkFailure(int exit_code) const {
  if (retry_attempted_ || user_input_detected_ || exit_code != 255) {
    return false;
  }
  return stderrIndicatesTransientNetworkFailure(terminalText());
}

void TerminalSessionWidget::updateTerminalWindowSize() {
#if defined(GMSSH_HAS_WEBTERMINAL)
  if (use_web_terminal_) {
#if defined(Q_OS_UNIX)
    if (pty_master_fd_ < 0) {
      return;
    }
    struct winsize size {};
    size.ws_col = static_cast<unsigned short>(std::max(20, terminal_cols_));
    size.ws_row = static_cast<unsigned short>(std::max(6, terminal_rows_));
    ::ioctl(pty_master_fd_, TIOCSWINSZ, &size);
#endif
    return;
  }
#endif

  if (output_view_ == nullptr) {
    return;
  }

  const QFontMetrics metrics(output_view_->font());
  terminal_cols_ = std::max(
      20, output_view_->viewport()->width() /
              std::max(1, metrics.horizontalAdvance(QChar::fromLatin1('M'))));
  terminal_rows_ =
      std::max(6, output_view_->viewport()->height() / std::max(1, metrics.lineSpacing()));

  if (in_alternate_screen_ || in_screen_repaint_mode_) {
    trimToTerminalViewportRows();
    renderTerminalBuffer();
  }

#if defined(Q_OS_UNIX)
  if (pty_master_fd_ < 0) {
    return;
  }
  struct winsize size {};
  size.ws_col = static_cast<unsigned short>(terminal_cols_);
  size.ws_row = static_cast<unsigned short>(terminal_rows_);
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

void TerminalSessionWidget::scrollToBottom() {
  if (output_view_ == nullptr) {
    return;
  }
  auto cursor = output_view_->textCursor();
  cursor.movePosition(QTextCursor::End);
  output_view_->setTextCursor(cursor);
  auto* scroll_bar = output_view_->verticalScrollBar();
  scroll_bar->setValue(scroll_bar->maximum());
  output_view_->ensureCursorVisible();
  QPointer<QPlainTextEdit> view = output_view_;
  QTimer::singleShot(0, output_view_, [view]() {
    if (view == nullptr) {
      return;
    }
    auto* deferred_scroll_bar = view->verticalScrollBar();
    deferred_scroll_bar->setValue(deferred_scroll_bar->maximum());
    view->ensureCursorVisible();
    view->viewport()->update();
  });
}

void TerminalSessionWidget::cleanup() {
  for (const auto& path : launch_plan_.cleanup_files) {
    QFile::remove(path);
  }
  launch_plan_.cleanup_files.clear();
}

}  // namespace gmssh

#if defined(GMSSH_HAS_WEBTERMINAL)
#include "terminal_session_widget.moc"
#endif
