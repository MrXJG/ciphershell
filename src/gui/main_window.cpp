#include "gui/main_window.h"

#include "gui/session_profile_dialog.h"
#include "gui/terminal_session_widget.h"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCheckBox>
#include <QCoreApplication>
#include <QCloseEvent>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QJsonObject>
#include <QLabel>
#include <QListWidgetItem>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QProcessEnvironment>
#include <QScreen>
#include <QSignalBlocker>
#include <QSettings>
#include <QSize>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyle>
#include <QTabBar>
#include <QTabWidget>
#include <QTcpSocket>
#include <QToolBar>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>

namespace gmssh {
namespace {

struct BinaryResolution {
  QString path;
  QString source;
};

constexpr auto kTerminalStatusProperty = "gmssh_status_text";

class TerminalTabCloseButton final : public QToolButton {
 public:
  explicit TerminalTabCloseButton(QWidget* parent = nullptr) : QToolButton(parent) {
    setObjectName(QStringLiteral("terminalTabCloseButton"));
    setFixedSize(24, 24);
    setAutoRaise(false);
    setCursor(Qt::PointingHandCursor);
    setToolTip(QStringLiteral("关闭终端标签页"));
    setFocusPolicy(Qt::NoFocus);
  }

 protected:
  void paintEvent(QPaintEvent*) override {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    const QRectF button_rect(0.0, 0.0, width(), height());
    if (isDown() || underMouse()) {
      painter.setPen(Qt::NoPen);
      painter.setBrush(isDown() ? QColor(QStringLiteral("#FECACA"))
                                : QColor(QStringLiteral("#FEE2E2")));
      painter.drawEllipse(button_rect.adjusted(1.5, 1.5, -1.5, -1.5));
    }

    const auto color = isDown() ? QColor(QStringLiteral("#7A271A"))
                               : (underMouse() ? QColor(QStringLiteral("#B42318"))
                                               : QColor(QStringLiteral("#374151")));
    QPen pen(color, 2.4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    painter.setPen(pen);

    const QPointF center = button_rect.center();
    constexpr qreal arm = 5.0;
    painter.drawLine(
        QPointF(center.x() - arm, center.y() - arm),
        QPointF(center.x() + arm, center.y() + arm));
    painter.drawLine(
        QPointF(center.x() + arm, center.y() - arm),
        QPointF(center.x() - arm, center.y() + arm));
  }
};

QString configRoot() {
  auto path = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  if (path.isEmpty()) {
    path = QDir::home().filePath(QStringLiteral(".gmssh-client"));
  }
  QDir().mkpath(path);
  return path;
}

QString appDataRoot() {
  auto path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  if (path.isEmpty()) {
    path = QDir::home().filePath(QStringLiteral(".gmssh-client"));
  }
  QDir().mkpath(path);
  return path;
}

QString auditLogPath() {
#if defined(Q_OS_WIN)
  const auto install_log_dir =
      QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("log"));
  const auto probe_path = QDir(install_log_dir).filePath(QStringLiteral(".write-test"));
  if (QDir().mkpath(install_log_dir)) {
    QFile probe(probe_path);
    if (probe.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
      probe.close();
      QFile::remove(probe_path);
      return QDir(install_log_dir).filePath(QStringLiteral("audit.log"));
    }
  }
#endif

  const auto fallback_log_dir = QDir(appDataRoot()).filePath(QStringLiteral("log"));
  QDir().mkpath(fallback_log_dir);
  return QDir(fallback_log_dir).filePath(QStringLiteral("audit.log"));
}

QString platformExecutableName(const QString& name) {
#if defined(Q_OS_WIN)
  if (!name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
    return QStringLiteral("%1.exe").arg(name);
  }
#endif
  return name;
}

std::optional<QString> promptPasswordWithSaveOption(
    QWidget* parent,
    bool default_save_credential,
    bool* save_credential) {
  QDialog dialog(parent);
  dialog.setWindowTitle(QStringLiteral("认证信息"));

  auto* layout = new QVBoxLayout(&dialog);
  layout->setContentsMargins(22, 18, 22, 18);
  layout->setSpacing(14);

  auto* label = new QLabel(QStringLiteral("请输入登录密码"), &dialog);
  layout->addWidget(label);

  auto* password_edit = new QLineEdit(&dialog);
  password_edit->setEchoMode(QLineEdit::Password);
  password_edit->setMinimumWidth(280);
  layout->addWidget(password_edit);

  auto* save_check = new QCheckBox(QStringLiteral("保存凭据（加密存储）"), &dialog);
  save_check->setChecked(default_save_credential);
  layout->addWidget(save_check);

  auto* buttons = new QDialogButtonBox(
      QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
      Qt::Horizontal,
      &dialog);
  layout->addWidget(buttons);

  QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

  password_edit->setFocus();
  if (dialog.exec() != QDialog::Accepted) {
    return std::nullopt;
  }

  if (save_credential != nullptr) {
    *save_credential = save_check->isChecked();
  }
  return password_edit->text();
}

BinaryResolution bundledOrSystemBinary(const QString& name) {
  struct Candidate {
    QString path;
    QString source;
  };

  const auto app_dir = QCoreApplication::applicationDirPath();
  const QDir app_dir_obj(app_dir);
  const auto env = QProcessEnvironment::systemEnvironment();
  const auto executable_name = platformExecutableName(name);

  QList<Candidate> candidates;
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("bin/%1").arg(executable_name)), QStringLiteral("app/bin")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../bin/%1").arg(executable_name)), QStringLiteral("../bin")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../../bin/%1").arg(executable_name)), QStringLiteral("../../bin")});
  candidates.push_back({app_dir_obj.filePath(QStringLiteral("../Resources/bin/%1").arg(executable_name)),
                        QStringLiteral("../Resources/bin")});
  candidates.push_back({app_dir_obj.filePath(QStringLiteral("../../Resources/bin/%1").arg(executable_name)),
                        QStringLiteral("../../Resources/bin")});

  const auto engine_dir = env.value(QStringLiteral("GMSSH_ENGINE_DIR")).trimmed();
  if (!engine_dir.isEmpty()) {
    candidates.push_back(
        {QDir(engine_dir).filePath(executable_name), QStringLiteral("GMSSH_ENGINE_DIR")});
  }

  const auto per_binary_var =
      (name == QStringLiteral("ssh")) ? QStringLiteral("GMSSH_SSH_PATH")
                                      : QStringLiteral("GMSSH_SFTP_PATH");
  const auto per_binary_path = env.value(per_binary_var).trimmed();
  if (!per_binary_path.isEmpty()) {
    candidates.push_back({per_binary_path, per_binary_var});
  }

  for (const auto& candidate : candidates) {
    QFileInfo info(candidate.path);
    if (!info.exists() || !info.isFile() || !info.isExecutable()) {
      continue;
    }

    const auto canonical = info.canonicalFilePath();
    return {
        canonical.isEmpty() ? info.absoluteFilePath() : canonical,
        candidate.source,
    };
  }

  return {executable_name, QStringLiteral("PATH(system)")};
}

BinaryResolution legacyBinary(const QString& name, const QString& modern_path) {
  struct Candidate {
    QString path;
    QString source;
  };

  const auto app_dir = QCoreApplication::applicationDirPath();
  const QDir app_dir_obj(app_dir);
  const auto env = QProcessEnvironment::systemEnvironment();
  const auto executable_name = platformExecutableName(name);
  const auto legacy_executable_name =
      platformExecutableName(QStringLiteral("%1-legacy-ecgm").arg(name));
  const auto modern_canonical = QFileInfo(modern_path).canonicalFilePath();
  const auto modern_normalized =
      modern_canonical.isEmpty() ? QFileInfo(modern_path).absoluteFilePath() : modern_canonical;

  QList<Candidate> candidates;
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("bin/%1").arg(legacy_executable_name)),
       QStringLiteral("app/bin-legacy")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../bin/%1").arg(legacy_executable_name)),
       QStringLiteral("../bin-legacy")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../../bin/%1").arg(legacy_executable_name)),
       QStringLiteral("../../bin-legacy")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("stage/bin/%1").arg(executable_name)),
       QStringLiteral("stage/bin")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../stage/bin/%1").arg(executable_name)),
       QStringLiteral("../stage/bin")});
  candidates.push_back(
      {app_dir_obj.filePath(QStringLiteral("../../stage/bin/%1").arg(executable_name)),
       QStringLiteral("../../stage/bin")});

  const auto legacy_dir = env.value(QStringLiteral("GMSSH_LEGACY_ENGINE_DIR")).trimmed();
  if (!legacy_dir.isEmpty()) {
    candidates.push_back(
        {QDir(legacy_dir).filePath(executable_name), QStringLiteral("GMSSH_LEGACY_ENGINE_DIR")});
  }

  const auto per_binary_legacy_var =
      (name == QStringLiteral("ssh")) ? QStringLiteral("GMSSH_SSH_LEGACY_PATH")
                                      : QStringLiteral("GMSSH_SFTP_LEGACY_PATH");
  const auto per_binary_legacy_path = env.value(per_binary_legacy_var).trimmed();
  if (!per_binary_legacy_path.isEmpty()) {
    candidates.push_back({per_binary_legacy_path, per_binary_legacy_var});
  }

  if (!modern_normalized.isEmpty()) {
    const QFileInfo modern_info(modern_normalized);
    const auto sibling_path =
        modern_info.dir().filePath(legacy_executable_name);
    candidates.push_back({sibling_path, QStringLiteral("sibling-of-modern")});
  }

  for (const auto& candidate : candidates) {
    QFileInfo info(candidate.path);
    if (!info.exists() || !info.isFile() || !info.isExecutable()) {
      continue;
    }

    const auto canonical = info.canonicalFilePath();
    const auto normalized = canonical.isEmpty() ? info.absoluteFilePath() : canonical;
    if (!modern_normalized.isEmpty() && normalized == modern_normalized) {
      continue;
    }

    return {normalized, candidate.source};
  }

  return {QString(), QStringLiteral("not-found")};
}

QSize initialWindowSize() {
  constexpr int kDefaultWidth = 1360;
  constexpr int kDefaultHeight = 840;
  constexpr qreal kScreenRatio = 0.84;

  const auto* screen = QGuiApplication::primaryScreen();
  if (screen == nullptr) {
    return QSize(kDefaultWidth, kDefaultHeight);
  }

  const auto available = screen->availableGeometry().size();
  const int width = std::max(
      1120,
      std::min(kDefaultWidth, static_cast<int>(available.width() * kScreenRatio)));
  const int height = std::max(
      700,
      std::min(kDefaultHeight, static_cast<int>(available.height() * kScreenRatio)));

  return QSize(width, height);
}

QString gmHostSignaturePolicyText(bool legacy_adaptation_enabled) {
  return legacy_adaptation_enabled ? QStringLiteral("旧版国密适配（降低校验强度）")
                                   : QStringLiteral("严格校验（推荐）");
}

QString connectionProtocolText(
    const ConnectionProfile& profile,
    const SshLaunchPlan& launch_plan) {
  QString protocol;
  switch (launch_plan.selected_mode) {
    case AlgorithmMode::GmOnly:
      protocol = QStringLiteral("国密 SSH");
      break;
    case AlgorithmMode::StandardOnly:
      protocol = QStringLiteral("标准 SSH");
      break;
    case AlgorithmMode::Auto:
      protocol = QStringLiteral("自动协商 SSH");
      break;
  }

  const auto route =
      profile.jump_host.trimmed().isEmpty() ? QStringLiteral("直连") : QStringLiteral("经跳板");

  QStringList details;
  if (launch_plan.selected_mode == AlgorithmMode::GmOnly) {
    details << QStringLiteral("sm2/ecgm + sm4 + hmac-sm3");
  }
  if (launch_plan.fallback_used) {
    details << QStringLiteral("已自动回退");
  }
  if (launch_plan.engine_fallback_used) {
    details << QStringLiteral("已切换引擎");
  }
  if (launch_plan.gm_hostsig_compatibility_bypass) {
    details << QStringLiteral("旧版国密适配");
  }

  auto text = QStringLiteral("%1 %2").arg(protocol, route);
  if (!details.isEmpty()) {
    text += QStringLiteral("（%1）").arg(details.join(QStringLiteral(" / ")));
  }
  return text;
}

QString mainWindowStyleSheet() {
  return QStringLiteral(R"(
* {
  font-family: "Segoe UI", "Inter", "PingFang SC", "Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
  font-weight: 400;
}
QMainWindow#mainWindow,
QDialog {
  background-color: #F7F8FA;
  color: #111318;
}
QWidget {
  color: #374151;
  selection-background-color: #DDEBFF;
  selection-color: #111318;
}
QToolTip {
  color: #111318;
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 8px;
  padding: 6px 8px;
}
QToolBar#mainToolbar {
  spacing: 10px;
  padding: 12px 14px;
  border: none;
  border-bottom: 1px solid #E8ECF2;
  background: #FFFFFF;
}
QToolBar#mainToolbar::separator {
  width: 1px;
  margin: 4px 8px;
  background: #E8ECF2;
}
QLabel#brandLabel {
  color: #0F766E;
  font-size: 18px;
  font-weight: 600;
  padding: 0 12px 0 4px;
}
QPushButton {
  min-height: 32px;
  border-radius: 16px;
  border: 1px solid #DDE2EA;
  background: #FFFFFF;
  color: #1F2937;
  padding: 0 12px;
  font-weight: 500;
}
QToolBar#mainToolbar QToolButton {
  min-height: 36px;
  border-radius: 18px;
  border: 1px solid #DDE2EA;
  background: #FFFFFF;
  color: #1F2937;
  padding: 0 16px;
  font-weight: 500;
}
QToolBar#mainToolbar QToolButton:hover,
QPushButton:hover {
  background: #F0F3F8;
  color: #111318;
  border-color: #C9D2DE;
}
QToolBar#mainToolbar QToolButton:pressed,
QPushButton:pressed,
QToolBar#mainToolbar QToolButton:checked {
  background: #E8F3F1;
  color: #0F766E;
  border-color: #9ED4CD;
}
QPushButton#primaryButton {
  min-height: 40px;
  border-radius: 20px;
  background: #0F766E;
  color: #FFFFFF;
  border: 1px solid #0F766E;
  font-weight: 600;
  padding: 0 16px;
}
QPushButton#primaryButton:hover {
  background: #0B665F;
  border-color: #0B665F;
  color: #FFFFFF;
}
QPushButton#primaryButton:pressed {
  background: #075B55;
  border-color: #075B55;
  color: #FFFFFF;
}
QPushButton:disabled,
QToolButton:disabled,
QPushButton#primaryButton:disabled {
  color: #98A2B3;
  background: #EEF1F5;
  border-color: #E1E6EE;
}
QFrame#leftPanel,
QFrame#terminalPanel,
QGroupBox,
QTabWidget::pane {
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 14px;
}
QFrame#leftPanel,
QFrame#terminalPanel {
  background: #FFFFFF;
}
QLabel#panelTitle {
  font-size: 24px;
  font-weight: 500;
  letter-spacing: -0.5px;
  color: #111318;
}
QLabel#panelSubtitle {
  font-size: 12px;
  letter-spacing: 1.6px;
  color: #6B7280;
}
QLabel {
  color: #374151;
}
QGroupBox {
  margin-top: 14px;
  padding: 14px 14px 12px 14px;
  color: #111318;
  font-size: 14px;
  font-weight: 600;
}
QGroupBox::title {
  subcontrol-origin: margin;
  left: 14px;
  padding: 0 8px;
  color: #111318;
  background: #FFFFFF;
}
QListWidget,
QPlainTextEdit,
QLineEdit,
QComboBox {
  border: 1px solid #DDE2EA;
  border-radius: 12px;
  background: #FFFFFF;
  color: #111318;
}
QLineEdit,
QComboBox {
  min-height: 30px;
  padding: 0 10px;
}
QLineEdit:focus,
QComboBox:focus {
  border-color: #2F6BFF;
}
QPlainTextEdit:focus,
QListWidget:focus {
  border-color: #DDE2EA;
  outline: 0;
}
QLineEdit:disabled,
QComboBox:disabled,
QPlainTextEdit:disabled {
  color: #98A2B3;
  background: #F0F3F8;
}
QLineEdit::placeholder {
  color: #98A2B3;
}
QComboBox {
  padding-right: 34px;
}
QComboBox::drop-down {
  subcontrol-origin: padding;
  subcontrol-position: top right;
  width: 32px;
  border: none;
  border-left: 1px solid #E8ECF2;
  background: transparent;
}
QComboBox::down-arrow {
  image: url(:/icons/icons/chevron-down.png);
  width: 14px;
  height: 14px;
}
QComboBox QAbstractItemView {
  background: #FFFFFF;
  color: #111318;
  border: 1px solid #DDE2EA;
  selection-background-color: #DDEBFF;
  selection-color: #111318;
  outline: 0;
}
QPlainTextEdit {
  padding: 10px;
  font-family: "Cascadia Mono", Consolas, "SF Mono", Menlo, "Microsoft YaHei UI", monospace;
  font-size: 13px;
  line-height: 1.2;
}
QListWidget#profileList,
QListWidget {
  padding: 6px;
  outline: 0;
}
QListWidget::item {
  min-height: 34px;
  padding: 8px 12px;
  border-radius: 10px;
  margin: 2px 0;
  color: #374151;
}
QListWidget::item:hover {
  background: #F0F3F8;
  color: #111318;
}
QListWidget::item:selected {
  background: #E8F3F1;
  color: #0F5F59;
}
QTableWidget {
  background: #FFFFFF;
  color: #111318;
  gridline-color: #E8ECF2;
  alternate-background-color: #FAFBFC;
  border: none;
  border-radius: 0;
  outline: 0;
}
QTableWidget:focus {
  border: none;
  outline: 0;
}
QFrame#forwardingTableFrame {
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 12px;
}
QTableWidget#forwardingRulesTable,
QTableWidget#forwardingRulesTable:focus {
  border: none;
  border-radius: 0;
  background: transparent;
  outline: 0;
}
QComboBox#forwardingRuleTypeCombo,
QComboBox#forwardingRuleTypeCombo:focus {
  min-height: 30px;
  border: 1px solid #C9D2DE;
  border-radius: 10px;
  background: #FFFFFF;
  padding: 0 32px 0 10px;
}
QComboBox#forwardingRuleTypeCombo:hover {
  border-color: #9ED4CD;
}
QComboBox#forwardingRuleTypeCombo:focus {
  border-color: #0F766E;
}
QComboBox#forwardingRuleTypeCombo::drop-down {
  subcontrol-origin: padding;
  subcontrol-position: top right;
  width: 30px;
  border: none;
  border-left: 1px solid #E8ECF2;
  background: #F7F8FA;
}
QComboBox#forwardingRuleTypeCombo::down-arrow {
  image: url(:/icons/icons/chevron-down.png);
  width: 15px;
  height: 15px;
}
QHeaderView::section {
  background: #F7F8FA;
  color: #374151;
  border: none;
  border-bottom: 1px solid #DDE2EA;
  padding: 8px 10px;
  font-weight: 600;
}
QTabWidget#terminalTabs::pane {
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 14px;
}
QTabWidget#terminalTabs::tab-bar {
  alignment: left;
  left: 0;
}
QTabBar {
  background: transparent;
  border: none;
  padding: 0;
}
QTabBar#terminalTabBar {
  background: transparent;
  border: none;
  padding: 0;
}
QTabBar#terminalTabBar::scroller {
  background: transparent;
}
QTabBar::tab {
  background: #F0F3F8;
  border: 1px solid #DDE2EA;
  border-radius: 10px;
  min-height: 26px;
  padding: 6px 14px;
  margin: 0 4px 4px 0;
  color: #6B7280;
}
QTabBar#terminalTabBar::tab {
  background: #F0F3F8;
  border: 1px solid #DDE2EA;
  border-radius: 12px;
  min-height: 30px;
  padding: 9px 8px 9px 16px;
  margin: 0 6px 6px 0;
  color: #6B7280;
}
QTabBar#terminalTabBar::tab:hover,
QTabBar::tab:hover {
  background: #E8ECF2;
  color: #111318;
}
QTabBar#terminalTabBar::tab:selected,
QTabBar::tab:selected {
  background: #FFFFFF;
  border-color: #9ED4CD;
  color: #0F5F59;
}
QTabWidget#sessionProfileTabs::pane {
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 12px;
}
QTabWidget#sessionProfileTabs::tab-bar {
  alignment: left;
  left: 0;
}
QTabBar#sessionProfileTabBar::tab {
  min-height: 28px;
  padding: 6px 16px;
  margin: 0 6px 5px 0;
  border-radius: 11px;
}
QToolButton#terminalTabCloseButton {
  min-width: 24px;
  min-height: 24px;
  max-width: 24px;
  max-height: 24px;
  padding: 0;
  margin: 0 0 0 8px;
  border: none;
  background: transparent;
}
QCheckBox {
  color: #374151;
  spacing: 8px;
}
QCheckBox::indicator {
  width: 16px;
  height: 16px;
  border-radius: 5px;
  border: 1px solid #C9D2DE;
  background: #FFFFFF;
}
QCheckBox::indicator:hover {
  border-color: #0F766E;
}
QCheckBox::indicator:checked {
  background: #0F766E;
  border-color: #0F766E;
  image: url(:/icons/icons/check-light.png);
}
QCheckBox::indicator:checked:disabled {
  background: #98A2B3;
  border-color: #98A2B3;
  image: url(:/icons/icons/check-light.png);
}
QMenuBar {
  background: #FFFFFF;
  color: #374151;
  border-bottom: 1px solid #E8ECF2;
}
QMenuBar::item {
  padding: 6px 10px;
  background: transparent;
}
QMenuBar::item:selected {
  background: #F0F3F8;
  color: #111318;
  border-radius: 6px;
}
QMenu {
  background: #FFFFFF;
  color: #374151;
  border: 1px solid #DDE2EA;
  border-radius: 10px;
  padding: 6px;
}
QMenu::item {
  padding: 8px 28px 8px 12px;
  border-radius: 8px;
}
QMenu::item:selected,
QMenu::item:checked {
  background: #E8F3F1;
  color: #0F5F59;
}
QMenu::separator {
  height: 1px;
  background: #E8ECF2;
  margin: 6px 8px;
}
QLabel#statusPill {
  padding: 8px 12px;
  border: 1px solid #B7DED8;
  border-radius: 12px;
  background: #EEF8F6;
  color: #0F5F59;
  font-weight: 500;
}
QStatusBar {
  min-height: 24px;
  padding: 0 12px;
  border: none;
  border-top: 1px solid #E8ECF2;
  background: #FFFFFF;
  color: #6B7280;
}
QStatusBar::item {
  border: none;
}
QSplitter::handle {
  background: transparent;
  margin: 4px;
}
QScrollBar:vertical,
QScrollBar:horizontal {
  background: transparent;
  border: none;
  margin: 4px;
}
QScrollBar::handle:vertical,
QScrollBar::handle:horizontal {
  background: #C9D2DE;
  border-radius: 5px;
  min-height: 28px;
  min-width: 28px;
}
QScrollBar::handle:hover {
  background: #98A2B3;
}
QScrollBar::add-line,
QScrollBar::sub-line,
QScrollBar::add-page,
QScrollBar::sub-page {
  background: transparent;
  border: none;
}
QDialogButtonBox QPushButton {
  min-width: 88px;
  min-height: 34px;
}
)");
}

bool isHostReachable(const QString& host, int port, int timeout_ms, QString* error) {
  QTcpSocket socket;
  socket.connectToHost(host, port);
  if (socket.waitForConnected(timeout_ms)) {
    socket.disconnectFromHost();
    return true;
  }

  if (error != nullptr) {
    *error = socket.errorString();
  }
  return false;
}

}  // namespace

MainWindow::MainWindow()
    : QMainWindow(),
      profile_repository_(QDir(configRoot()).filePath(QStringLiteral("profiles.json"))),
      credential_store_(QDir(configRoot()).filePath(QStringLiteral("credentials.json"))),
      audit_logger_(auditLogPath()),
      ssh_adapter_(&audit_logger_) {
  setObjectName(QStringLiteral("mainWindow"));
  setWindowTitle(QStringLiteral("CipherShell"));
  resize(initialWindowSize());

  const auto ssh_resolution = bundledOrSystemBinary(QStringLiteral("ssh"));
  const auto sftp_resolution = bundledOrSystemBinary(QStringLiteral("sftp"));
  const auto legacy_ssh_resolution = legacyBinary(QStringLiteral("ssh"), ssh_resolution.path);
  const auto legacy_sftp_resolution = legacyBinary(QStringLiteral("sftp"), sftp_resolution.path);
  ssh_adapter_.setSshBinaryPath(ssh_resolution.path);
  ssh_adapter_.setSftpBinaryPath(sftp_resolution.path);
  ssh_adapter_.setLegacySshBinaryPath(legacy_ssh_resolution.path);
  ssh_adapter_.setLegacySftpBinaryPath(legacy_sftp_resolution.path);
  ssh_adapter_.setKnownHostsPath(QDir(configRoot()).filePath(QStringLiteral("known_hosts")));

  audit_logger_.logEvent(
      QStringLiteral("engine_binary_resolved"),
      QJsonObject{
          {QStringLiteral("ssh_path"), ssh_resolution.path},
          {QStringLiteral("ssh_source"), ssh_resolution.source},
          {QStringLiteral("sftp_path"), sftp_resolution.path},
          {QStringLiteral("sftp_source"), sftp_resolution.source},
          {QStringLiteral("legacy_ssh_path"), legacy_ssh_resolution.path},
          {QStringLiteral("legacy_ssh_source"), legacy_ssh_resolution.source},
          {QStringLiteral("legacy_sftp_path"), legacy_sftp_resolution.path},
          {QStringLiteral("legacy_sftp_source"), legacy_sftp_resolution.source},
      });

  auto* tool_bar = addToolBar(QStringLiteral("主工具栏"));
  tool_bar->setObjectName(QStringLiteral("mainToolbar"));
  tool_bar->setToolButtonStyle(Qt::ToolButtonTextOnly);
  tool_bar->setIconSize(QSize(18, 18));
  tool_bar->setMovable(false);

  auto* brand_label = new QLabel(QStringLiteral("CipherShell"), tool_bar);
  brand_label->setObjectName(QStringLiteral("brandLabel"));
  tool_bar->addWidget(brand_label);
  tool_bar->addSeparator();

  auto* new_action = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_FileDialogNewFolder),
      QStringLiteral("新建"));
  edit_action_ = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_FileDialogDetailedView),
      QStringLiteral("编辑"));
  auto* delete_action = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_TrashIcon),
      QStringLiteral("删除"));
  tool_bar->addSeparator();
  auto* connect_action = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_ArrowForward),
      QStringLiteral("连接"));
  open_sftp_action_ = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_DirOpenIcon),
      QStringLiteral("SFTP"));
  open_audit_action_ = tool_bar->addAction(
      style()->standardIcon(QStyle::SP_FileDialogContentsView),
      QStringLiteral("审计日志"));

  auto* tool_spacer = new QWidget(tool_bar);
  tool_spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  tool_bar->addWidget(tool_spacer);

  auto* file_menu = menuBar()->addMenu(QStringLiteral("文件"));
  file_menu->addAction(new_action);
  file_menu->addAction(edit_action_);
  file_menu->addAction(delete_action);
  file_menu->addSeparator();
  file_menu->addAction(QStringLiteral("退出"), this, &QWidget::close);

  auto* session_menu = menuBar()->addMenu(QStringLiteral("会话"));
  session_menu->addAction(connect_action);

  auto* tools_menu = menuBar()->addMenu(QStringLiteral("工具"));
  tools_menu->addAction(open_sftp_action_);
  tools_menu->addAction(open_audit_action_);

  auto* security_menu = menuBar()->addMenu(QStringLiteral("安全"));
  strict_hostsig_action_ =
      security_menu->addAction(QStringLiteral("国密主机签名严格校验（推荐）"));
  strict_hostsig_action_->setCheckable(true);
  compat_hostsig_action_ =
      security_menu->addAction(QStringLiteral("国密旧版服务端适配（降低校验强度）"));
  compat_hostsig_action_->setCheckable(true);
  auto* hostsig_group = new QActionGroup(this);
  hostsig_group->setExclusive(true);
  hostsig_group->addAction(strict_hostsig_action_);
  hostsig_group->addAction(compat_hostsig_action_);
  strict_hostsig_action_->setChecked(true);

  auto* central = new QWidget(this);
  auto* root_layout = new QVBoxLayout(central);
  root_layout->setContentsMargins(12, 12, 12, 12);
  root_layout->setSpacing(12);

  main_splitter_ = new QSplitter(Qt::Horizontal, central);
  main_splitter_->setChildrenCollapsible(false);
  root_layout->addWidget(main_splitter_);

  auto* left_panel = new QFrame(main_splitter_);
  left_panel->setObjectName(QStringLiteral("leftPanel"));
  left_panel->setMinimumWidth(200);
  left_panel->setMaximumWidth(240);

  auto* left_layout = new QVBoxLayout(left_panel);
  left_layout->setContentsMargins(14, 14, 14, 14);
  left_layout->setSpacing(10);

  auto* nav_title = new QLabel(QStringLiteral("会话中心"), left_panel);
  nav_title->setObjectName(QStringLiteral("panelTitle"));
  left_layout->addWidget(nav_title);
  auto* nav_subtitle =
      new QLabel(QStringLiteral("SESSION CENTER · 配置、保存、连接"), left_panel);
  nav_subtitle->setObjectName(QStringLiteral("panelSubtitle"));
  left_layout->addWidget(nav_subtitle);

  auto* filter_row = new QHBoxLayout();
  filter_row->setContentsMargins(0, 0, 0, 0);
  filter_row->setSpacing(8);
  auto* filter_label = new QLabel(QStringLiteral("筛选"), left_panel);
  filter_label->setObjectName(QStringLiteral("panelSubtitle"));
  search_edit_ = new QLineEdit(left_panel);
  search_edit_->setClearButtonEnabled(true);
  search_edit_->setPlaceholderText(QStringLiteral("按名称 / 主机过滤"));
  search_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  filter_row->addWidget(filter_label);
  filter_row->addWidget(search_edit_, 1);
  left_layout->addLayout(filter_row);

  profile_list_ = new QListWidget(left_panel);
  profile_list_->setObjectName(QStringLiteral("profileList"));
  profile_list_->setAlternatingRowColors(false);
  profile_list_->setSelectionMode(QAbstractItemView::SingleSelection);
  left_layout->addWidget(profile_list_, 1);

  auto* left_buttons = new QHBoxLayout();
  left_buttons->setSpacing(8);
  new_button_ = new QPushButton(QStringLiteral("新建"), left_panel);
  edit_button_ = new QPushButton(QStringLiteral("编辑"), left_panel);
  delete_button_ = new QPushButton(QStringLiteral("删除"), left_panel);
  for (auto* button : {new_button_, edit_button_, delete_button_}) {
    button->setMinimumWidth(0);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  }
  left_buttons->addWidget(new_button_);
  left_buttons->addWidget(edit_button_);
  left_buttons->addWidget(delete_button_);
  left_layout->addLayout(left_buttons);

  connect_button_ = new QPushButton(QStringLiteral("连接当前会话"), left_panel);
  connect_button_->setObjectName(QStringLiteral("primaryButton"));
  connect_button_->setMinimumHeight(42);
  left_layout->addWidget(connect_button_);

  auto* terminal_panel = new QFrame(main_splitter_);
  terminal_panel->setObjectName(QStringLiteral("terminalPanel"));

  auto* terminal_layout = new QVBoxLayout(terminal_panel);
  terminal_layout->setContentsMargins(14, 14, 14, 14);
  terminal_layout->setSpacing(10);

  auto* terminal_title = new QLabel(QStringLiteral("终端工作区"), terminal_panel);
  terminal_title->setObjectName(QStringLiteral("panelTitle"));
  terminal_layout->addWidget(terminal_title);
  auto* terminal_subtitle = new QLabel(
      QStringLiteral("TERMINAL WORKSPACE · 多会话命令与国密协商"),
      terminal_panel);
  terminal_subtitle->setObjectName(QStringLiteral("panelSubtitle"));
  terminal_layout->addWidget(terminal_subtitle);

  terminal_tabs_ = new QTabWidget(terminal_panel);
  terminal_tabs_->setObjectName(QStringLiteral("terminalTabs"));
  terminal_tabs_->setTabsClosable(false);
  terminal_tabs_->setMovable(true);
  terminal_tabs_->setDocumentMode(false);
  terminal_tabs_->setUsesScrollButtons(true);
  auto* terminal_tab_bar = terminal_tabs_->tabBar();
  terminal_tab_bar->setObjectName(QStringLiteral("terminalTabBar"));
  terminal_tab_bar->setDrawBase(false);
  terminal_tab_bar->setExpanding(false);
  terminal_tab_bar->setElideMode(Qt::ElideRight);
  terminal_tab_bar->setMouseTracking(true);
  terminal_layout->addWidget(terminal_tabs_, 1);

  connection_status_label_ = new QLabel(QStringLiteral("状态：未连接"), terminal_panel);
  connection_status_label_->setObjectName(QStringLiteral("statusPill"));
  terminal_layout->addWidget(connection_status_label_);

  main_splitter_->addWidget(left_panel);
  main_splitter_->addWidget(terminal_panel);
  main_splitter_->setStretchFactor(0, 0);
  main_splitter_->setStretchFactor(1, 1);
  main_splitter_->setSizes({210, 1350});

  setCentralWidget(central);
  applyVisualStyle();

  statusBar()->showMessage(
      legacy_ssh_resolution.path.isEmpty()
          ? QStringLiteral("就绪（SSH 引擎来源：%1）").arg(ssh_resolution.source)
          : QStringLiteral("就绪（主引擎：%1；旧版国密引擎：%2）")
                .arg(ssh_resolution.source, legacy_ssh_resolution.source));

  connect(profile_list_, &QListWidget::currentRowChanged, this, &MainWindow::onProfileSelected);
  connect(profile_list_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) {
    onEditProfile();
  });

  connect(new_button_, &QPushButton::clicked, this, &MainWindow::onNewProfile);
  connect(edit_button_, &QPushButton::clicked, this, &MainWindow::onEditProfile);
  connect(delete_button_, &QPushButton::clicked, this, &MainWindow::onDeleteProfile);
  connect(connect_button_, &QPushButton::clicked, this, &MainWindow::onConnect);

  connect(new_action, &QAction::triggered, this, &MainWindow::onNewProfile);
  connect(edit_action_, &QAction::triggered, this, &MainWindow::onEditProfile);
  connect(delete_action, &QAction::triggered, this, &MainWindow::onDeleteProfile);
  connect(connect_action, &QAction::triggered, this, &MainWindow::onConnect);
  connect(open_sftp_action_, &QAction::triggered, this, &MainWindow::onOpenSftpTool);
  connect(open_audit_action_, &QAction::triggered, this, &MainWindow::onOpenAuditLog);
  connect(strict_hostsig_action_, &QAction::triggered, this, [this]() {
    applyGmHostSignaturePolicy(false);
  });
  connect(compat_hostsig_action_, &QAction::triggered, this, [this]() {
    applyGmHostSignaturePolicy(true);
  });

  connect(search_edit_, &QLineEdit::textChanged, this, &MainWindow::applyProfileFilter);

  connect(terminal_tabs_, &QTabWidget::currentChanged, this, [this](int) {
    updateActiveTerminalStatus();
    if (sftp_window_ != nullptr && sftp_window_->isVisible()) {
      syncSftpPanelToCurrentTerminal();
    }
  });

  restoreUiState();
  reloadProfiles();
}

void MainWindow::closeEvent(QCloseEvent* event) {
  persistUiState();
  QMainWindow::closeEvent(event);
}

void MainWindow::restoreUiState() {
  QSettings settings;

  const auto geometry = settings.value(QStringLiteral("ui/window_geometry")).toByteArray();
  if (!geometry.isEmpty()) {
    restoreGeometry(geometry);
  }

  const auto* screen = QGuiApplication::primaryScreen();
  if (screen != nullptr) {
    const auto available = screen->availableGeometry().size();
    const int max_width = static_cast<int>(available.width() * 0.9);
    const int max_height = static_cast<int>(available.height() * 0.9);
    if (width() > max_width || height() > max_height) {
      resize(std::min(width(), max_width), std::min(height(), max_height));
    }
  }

  if (main_splitter_ != nullptr) {
    const auto splitter_state =
        settings.value(QStringLiteral("ui/main_splitter_state")).toByteArray();
    if (!splitter_state.isEmpty()) {
      main_splitter_->restoreState(splitter_state);
    }
  }

  const bool compat_bypass =
      settings.value(QStringLiteral("security/gm_hostsig_compat_bypass"), false).toBool();
  if (strict_hostsig_action_ != nullptr && compat_hostsig_action_ != nullptr) {
    const QSignalBlocker block_strict(strict_hostsig_action_);
    const QSignalBlocker block_compat(compat_hostsig_action_);
    strict_hostsig_action_->setChecked(!compat_bypass);
    compat_hostsig_action_->setChecked(compat_bypass);
  }
  applyGmHostSignaturePolicy(compat_bypass);
}

void MainWindow::persistUiState() const {
  QSettings settings;
  settings.setValue(QStringLiteral("ui/window_geometry"), saveGeometry());

  if (main_splitter_ != nullptr) {
    settings.setValue(QStringLiteral("ui/main_splitter_state"), main_splitter_->saveState());
  }
  settings.setValue(
      QStringLiteral("security/gm_hostsig_compat_bypass"),
      ssh_adapter_.gmHostSignaturePolicy() == GmHostSignaturePolicy::CompatibilityBypass);
}

void MainWindow::closeTerminalTab(int idx) {
  if (terminal_tabs_ == nullptr || idx < 0 || idx >= terminal_tabs_->count()) {
    return;
  }

  auto* widget = terminal_tabs_->widget(idx);
  terminal_tabs_->removeTab(idx);
  if (widget != nullptr) {
    widget->deleteLater();
  }
  updateActiveTerminalStatus();
  if (sftp_window_ != nullptr && sftp_window_->isVisible()) {
    syncSftpPanelToCurrentTerminal();
  }
}

void MainWindow::installTerminalTabCloseButton(int idx, QWidget* tab_widget) {
  if (terminal_tabs_ == nullptr || tab_widget == nullptr || idx < 0) {
    return;
  }

  auto* close_button = new TerminalTabCloseButton(terminal_tabs_->tabBar());
  terminal_tabs_->tabBar()->setTabButton(idx, QTabBar::RightSide, close_button);

  connect(close_button, &QToolButton::clicked, this, [this, tab_widget]() {
    if (terminal_tabs_ == nullptr) {
      return;
    }
    closeTerminalTab(terminal_tabs_->indexOf(tab_widget));
  });
}

void MainWindow::reloadProfiles() {
  QString error;
  profiles_ = profile_repository_.loadAll(&error);

  profile_list_->clear();
  for (const auto& profile : profiles_) {
    auto* item = new QListWidgetItem(profile.name, profile_list_);
    item->setToolTip(QStringLiteral("%1@%2:%3").arg(profile.username).arg(profile.host).arg(profile.port));
  }

  applyProfileFilter(search_edit_ != nullptr ? search_edit_->text() : QString());

  if (!error.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("会话配置"), error);
  }

  bool selected = false;
  for (int i = 0; i < profile_list_->count(); ++i) {
    auto* item = profile_list_->item(i);
    if (item != nullptr && !item->isHidden()) {
      profile_list_->setCurrentRow(i);
      selected = true;
      break;
    }
  }

  if (!selected) {
    updateConnectionStatus(QStringLiteral("暂无会话，请先新建连接配置"));
  }
}

void MainWindow::applyProfileFilter(const QString& keyword) {
  const auto query = keyword.trimmed();
  for (int i = 0; i < profile_list_->count(); ++i) {
    auto* item = profile_list_->item(i);
    if (item == nullptr || i >= profiles_.size()) {
      continue;
    }

    const auto& profile = profiles_[i];
    const bool visible = query.isEmpty() ||
                         profile.name.contains(query, Qt::CaseInsensitive) ||
                         profile.host.contains(query, Qt::CaseInsensitive);
    item->setHidden(!visible);
  }
}

void MainWindow::updateConnectionStatus(const QString& text) {
  if (connection_status_label_ != nullptr) {
    connection_status_label_->setText(QStringLiteral("状态：%1").arg(text));
  }
}

void MainWindow::applyVisualStyle() {
  qApp->setStyleSheet(mainWindowStyleSheet());
}

void MainWindow::applyGmHostSignaturePolicy(bool compatibility_bypass) {
  const auto target_policy = compatibility_bypass ? GmHostSignaturePolicy::CompatibilityBypass
                                                  : GmHostSignaturePolicy::Strict;
  const bool changed = ssh_adapter_.gmHostSignaturePolicy() != target_policy;
  ssh_adapter_.setGmHostSignaturePolicy(target_policy);

  if (!changed) {
    return;
  }

  const auto policy_text = gmHostSignaturePolicyText(compatibility_bypass);
  statusBar()->showMessage(
      QStringLiteral("国密主机签名校验已切换为：%1").arg(policy_text),
      3200);
  updateConnectionStatus(QStringLiteral("国密主机签名校验：%1").arg(policy_text));
  audit_logger_.logEvent(
      QStringLiteral("hostsig_policy_changed"),
      QJsonObject{
          {QStringLiteral("compatibility_bypass"), compatibility_bypass},
      });
}

void MainWindow::onProfileSelected(int row) {
  if (row < 0 || row >= profiles_.size()) {
    return;
  }

  const auto& profile = profiles_[row];
  updateConnectionStatus(
      QStringLiteral("已选中会话：%1 (%2@%3:%4)")
          .arg(profile.name)
          .arg(profile.username)
          .arg(profile.host)
          .arg(profile.port));
}

void MainWindow::updateActiveTerminalStatus() {
  if (terminal_tabs_ == nullptr || terminal_tabs_->count() == 0) {
    const auto profile = selectedProfile();
    if (profile.has_value()) {
      updateConnectionStatus(
          QStringLiteral("已选中会话：%1 (%2@%3:%4)")
              .arg(profile->name)
              .arg(profile->username)
              .arg(profile->host)
              .arg(profile->port));
    } else {
      updateConnectionStatus(QStringLiteral("未连接"));
    }
    return;
  }

  auto* current = terminal_tabs_->currentWidget();
  if (current == nullptr) {
    updateConnectionStatus(QStringLiteral("未连接"));
    return;
  }

  const auto status_text = current->property(kTerminalStatusProperty).toString().trimmed();
  if (status_text.isEmpty()) {
    updateConnectionStatus(QStringLiteral("当前终端标签无连接状态"));
    return;
  }
  updateConnectionStatus(status_text);
}

TerminalSessionWidget* MainWindow::currentTerminalSession() const {
  if (terminal_tabs_ == nullptr) {
    return nullptr;
  }
  return qobject_cast<TerminalSessionWidget*>(terminal_tabs_->currentWidget());
}

bool MainWindow::syncSftpPanelToCurrentTerminal() {
  if (sftp_panel_ == nullptr) {
    return false;
  }

  auto* session = currentTerminalSession();
  if (session == nullptr) {
    sftp_panel_->clearContext();
    return false;
  }

  sftp_panel_->setContext(session->profile(), session->secrets());
  return true;
}

bool MainWindow::validateProfile(const ConnectionProfile& profile, QString* error) const {
  if (profile.name.trimmed().isEmpty() || profile.host.trimmed().isEmpty() ||
      profile.username.trimmed().isEmpty()) {
    if (error != nullptr) {
      *error = QStringLiteral("名称、主机、用户名不能为空。");
    }
    return false;
  }
  if (profile.port <= 0 || profile.port > 65535) {
    if (error != nullptr) {
      *error = QStringLiteral("端口必须在 1-65535 范围内。");
    }
    return false;
  }
  return true;
}

int MainWindow::findProfileByName(const QString& name) const {
  for (int i = 0; i < profiles_.size(); ++i) {
    if (profiles_[i].name == name) {
      return i;
    }
  }
  return -1;
}

bool MainWindow::editProfile(int row, bool creating_new) {
  SessionProfileDialog dialog(this);
  dialog.setDialogTitle(creating_new ? QStringLiteral("新建会话") : QStringLiteral("编辑会话"));

  ConnectionProfile original;
  if (creating_new) {
    dialog.setProfile(ConnectionProfile{});
  } else {
    if (row < 0 || row >= profiles_.size()) {
      QMessageBox::information(this, QStringLiteral("会话配置"), QStringLiteral("请先选择一个会话。"));
      return false;
    }
    original = profiles_[row];
    dialog.setProfile(original);
  }

  while (true) {
    if (dialog.exec() != QDialog::Accepted) {
      return false;
    }

    const auto edited = dialog.profile();

    QString validate_error;
    if (!validateProfile(edited, &validate_error)) {
      QMessageBox::warning(this, QStringLiteral("参数校验"), validate_error);
      continue;
    }

    const int existing = findProfileByName(edited.name);
    if (existing >= 0 && (creating_new || existing != row)) {
      QMessageBox::warning(this, QStringLiteral("会话配置"), QStringLiteral("配置名称已存在，请更换名称。"));
      continue;
    }

    auto next_profiles = profiles_;
    if (creating_new) {
      next_profiles.push_back(edited);
    } else {
      next_profiles[row] = edited;
    }

    QString save_error;
    if (!profile_repository_.saveAll(next_profiles, &save_error)) {
      QMessageBox::warning(this, QStringLiteral("会话配置"), save_error);
      continue;
    }

    profiles_ = std::move(next_profiles);

    if (!edited.save_credential) {
      credential_store_.removePassword(edited.name);
    }
    if (!creating_new && original.name != edited.name) {
      credential_store_.removePassword(original.name);
    }

    audit_logger_.logEvent(
        QStringLiteral("profile_saved"),
        QJsonObject{{QStringLiteral("profile"), edited.name}});

    reloadProfiles();
    const auto matches = profile_list_->findItems(edited.name, Qt::MatchExactly);
    if (!matches.isEmpty()) {
      profile_list_->setCurrentItem(matches.first());
    }

    statusBar()->showMessage(
        creating_new ? QStringLiteral("会话配置已创建") : QStringLiteral("会话配置已更新"),
        2500);
    return true;
  }
}

void MainWindow::onNewProfile() {
  editProfile(-1, true);
}

void MainWindow::onEditProfile() {
  editProfile(profile_list_->currentRow(), false);
}

void MainWindow::onDeleteProfile() {
  const auto row = profile_list_->currentRow();
  if (row < 0 || row >= profiles_.size()) {
    return;
  }

  const auto profile_name = profiles_[row].name;
  profiles_.remove(row);

  QString error;
  if (!profile_repository_.saveAll(profiles_, &error)) {
    QMessageBox::warning(this, QStringLiteral("会话配置"), error);
    return;
  }

  credential_store_.removePassword(profile_name);

  audit_logger_.logEvent(
      QStringLiteral("profile_deleted"),
      QJsonObject{{QStringLiteral("profile"), profile_name}});

  reloadProfiles();
  statusBar()->showMessage(QStringLiteral("已删除会话：%1").arg(profile_name), 2500);
}

std::optional<ConnectionProfile> MainWindow::selectedProfile() const {
  const auto row = profile_list_->currentRow();
  if (row < 0 || row >= profiles_.size()) {
    return std::nullopt;
  }
  return profiles_[row];
}

std::optional<SessionSecrets> MainWindow::collectSecretsForConnect(ConnectionProfile& profile) {
  SessionSecrets secrets;

  if (profile.save_credential) {
    const auto loaded = credential_store_.loadPassword(profile.name);
    if (loaded.ok) {
      secrets.password = loaded.value;
    }
  }

  if (profile.auth_method == AuthMethod::Password && secrets.password.isEmpty()) {
    bool save_credential = profile.save_credential;
    const auto password = promptPasswordWithSaveOption(this, profile.save_credential, &save_credential);
    if (!password.has_value()) {
      return std::nullopt;
    }
    if (password->isEmpty()) {
      QMessageBox::warning(
          this,
          QStringLiteral("认证信息"),
          QStringLiteral("当前认证方式为密码登录，密码不能为空。"));
      return std::nullopt;
    }
    profile.save_credential = save_credential;
    secrets.password = password.value();
  }

  if (profile.auth_method == AuthMethod::X509Sm2Cert && !profile.pfx_path.trimmed().isEmpty()) {
    bool ok = false;
    const auto pfx_password = QInputDialog::getText(
        this,
        QStringLiteral("认证信息"),
        QStringLiteral("请输入 PFX 密码（可留空）"),
        QLineEdit::Password,
        QString(),
        &ok);
    if (!ok) {
      return std::nullopt;
    }
    secrets.pfx_password = pfx_password;
  }

  return secrets;
}

void MainWindow::onConnect() {
  const auto row = profile_list_->currentRow();
  if (row < 0 || row >= profiles_.size()) {
    QMessageBox::information(this, QStringLiteral("连接"), QStringLiteral("请先选择一个会话。"));
    return;
  }
  auto profile = profiles_[row];
  const bool original_save_credential = profile.save_credential;

  const auto secrets_result = collectSecretsForConnect(profile);
  if (!secrets_result.has_value()) {
    updateConnectionStatus(QStringLiteral("已取消连接"));
    return;
  }
  auto secrets = secrets_result.value();

  if (profile.save_credential != original_save_credential) {
    profiles_[row].save_credential = profile.save_credential;
    QString save_error;
    if (!profile_repository_.saveAll(profiles_, &save_error)) {
      QMessageBox::warning(this, QStringLiteral("会话配置"), save_error);
      updateConnectionStatus(QStringLiteral("连接取消：保存凭据选项写入失败"));
      return;
    }
    if (!profile.save_credential) {
      credential_store_.removePassword(profile.name);
    }
  }

  updateConnectionStatus(QStringLiteral("正在检查网络：%1:%2").arg(profile.host).arg(profile.port));

  QString network_error;
  if (!isHostReachable(profile.host, profile.port, 3000, &network_error)) {
    const auto message = QStringLiteral("无法连接到 %1:%2。\n原因：%3")
                             .arg(profile.host)
                             .arg(profile.port)
                             .arg(network_error);
    QMessageBox::warning(this, QStringLiteral("网络不可达"), message);
    audit_logger_.logEvent(
        QStringLiteral("connect_precheck_failed"),
        QJsonObject{{QStringLiteral("profile"), profile.name},
                    {QStringLiteral("host"), profile.host},
                    {QStringLiteral("port"), profile.port},
                    {QStringLiteral("error"), network_error}});
    updateConnectionStatus(QStringLiteral("网络不可达"));
    statusBar()->showMessage(QStringLiteral("连接失败：网络不可达"), 4000);
    return;
  }

  if (profile.save_credential && !secrets.password.isEmpty()) {
    const auto saved = credential_store_.savePassword(profile.name, secrets.password);
    if (!saved.ok) {
      audit_logger_.logEvent(
          QStringLiteral("credential_save_failed"),
          QJsonObject{{QStringLiteral("profile"), profile.name},
                      {QStringLiteral("error"), saved.error}});
    }
  }

  updateConnectionStatus(QStringLiteral("正在建立 SSH 会话..."));

  const auto launch_plan = ssh_adapter_.prepareLaunch(profile, secrets);
  if (!launch_plan.ok) {
    const auto detail = QStringLiteral("%1\n\n当前 SSH 引擎：%2")
                            .arg(launch_plan.error, ssh_adapter_.sshBinaryPath());
    QMessageBox::warning(this, QStringLiteral("连接失败"), detail);
    audit_logger_.logEvent(
        QStringLiteral("connect_failed"),
        QJsonObject{{QStringLiteral("profile"), profile.name},
                    {QStringLiteral("error"), launch_plan.error},
                    {QStringLiteral("ssh_program"), ssh_adapter_.sshBinaryPath()}});
    updateConnectionStatus(QStringLiteral("连接失败"));
    statusBar()->showMessage(QStringLiteral("连接失败"), 4000);
    return;
  }

  auto* session = new TerminalSessionWidget(
      profile.name,
      profile,
      secrets,
      launch_plan,
      &audit_logger_,
      terminal_tabs_);
  const auto connected_status =
      QStringLiteral("已连接：%1@%2:%3  ｜  连接方式：%4")
          .arg(profile.username)
          .arg(profile.host)
          .arg(profile.port)
          .arg(connectionProtocolText(profile, launch_plan));
  session->setProperty(kTerminalStatusProperty, connected_status);
  const auto tab_idx = terminal_tabs_->addTab(session, profile.name);
  installTerminalTabCloseButton(tab_idx, session);
  terminal_tabs_->setCurrentIndex(tab_idx);

  connect(
      session,
      &TerminalSessionWidget::sessionClosed,
      this,
      [this, session](const QString& session_name) {
        session->setProperty(
            kTerminalStatusProperty,
            QStringLiteral("会话已断开：%1").arg(session_name));
        if (terminal_tabs_ != nullptr && terminal_tabs_->currentWidget() == session) {
          updateActiveTerminalStatus();
        }
        statusBar()->showMessage(QStringLiteral("会话已断开"), 3000);
        if (audit_view_ != nullptr) {
          audit_view_->refresh();
        }
      });

  ensureToolWindows();
  syncSftpPanelToCurrentTerminal();

  audit_logger_.logEvent(
      QStringLiteral("connect_started"),
      QJsonObject{{QStringLiteral("profile"), profile.name},
                  {QStringLiteral("ssh_program"), launch_plan.program},
                  {QStringLiteral("selected_mode"), toString(launch_plan.selected_mode)},
                  {QStringLiteral("gm_hostsig_compatibility_bypass"),
                   launch_plan.gm_hostsig_compatibility_bypass},
                  {QStringLiteral("fallback_used"), launch_plan.fallback_used},
                  {QStringLiteral("fallback_reason"), launch_plan.fallback_reason},
                  {QStringLiteral("engine_fallback_used"), launch_plan.engine_fallback_used},
                  {QStringLiteral("engine_fallback_reason"), launch_plan.engine_fallback_reason},
                  {QStringLiteral("engine_fallback_from"), launch_plan.engine_fallback_from},
                  {QStringLiteral("engine_fallback_to"), launch_plan.engine_fallback_to}});

  updateActiveTerminalStatus();
  statusBar()->showMessage(QStringLiteral("连接成功"), 2500);
  if (audit_view_ != nullptr) {
    audit_view_->refresh();
  }
}

void MainWindow::ensureToolWindows() {
  if (sftp_window_ == nullptr) {
    sftp_window_ = new QDialog(this);
    sftp_window_->setModal(false);
    sftp_window_->setWindowTitle(QStringLiteral("SFTP 工具"));
    sftp_window_->resize(980, 620);

    auto* layout = new QVBoxLayout(sftp_window_);
    layout->setContentsMargins(10, 10, 10, 10);
    sftp_panel_ = new SftpPanel(sftp_window_);
    sftp_panel_->setEngineAdapter(&ssh_adapter_);
    sftp_panel_->setAuditLogger(&audit_logger_);
    layout->addWidget(sftp_panel_);
  }

  if (audit_window_ == nullptr) {
    audit_window_ = new QDialog(this);
    audit_window_->setModal(false);
    audit_window_->setWindowTitle(QStringLiteral("审计日志"));
    audit_window_->resize(980, 620);

    auto* layout = new QVBoxLayout(audit_window_);
    layout->setContentsMargins(10, 10, 10, 10);
    audit_view_ = new AuditLogView(audit_window_);
    audit_view_->setLogFilePath(audit_logger_.logFilePath());
    layout->addWidget(audit_view_);
  }
}

void MainWindow::onOpenSftpTool() {
  ensureToolWindows();
  if (!syncSftpPanelToCurrentTerminal()) {
    QMessageBox::information(
        this,
        QStringLiteral("SFTP"),
        QStringLiteral("请先切换到一个已连接的终端标签，再打开 SFTP。"));
    return;
  }
  sftp_window_->show();
  sftp_window_->raise();
  sftp_window_->activateWindow();
  sftp_panel_->refreshPendingInitial();
}

void MainWindow::onOpenAuditLog() {
  ensureToolWindows();
  audit_view_->refresh();
  audit_window_->show();
  audit_window_->raise();
  audit_window_->activateWindow();
}

}  // namespace gmssh
