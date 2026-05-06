#include "gui/main_window.h"

#include "gui/session_profile_dialog.h"
#include "gui/terminal_session_widget.h"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QCloseEvent>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QJsonObject>
#include <QLabel>
#include <QListWidgetItem>
#include <QMenuBar>
#include <QMessageBox>
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
#include <QTimer>
#include <QToolBar>
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

QString gmHostSignaturePolicyText(GmHostSignaturePolicy policy) {
  switch (policy) {
    case GmHostSignaturePolicy::Auto:
      return QStringLiteral("自动（推荐）");
    case GmHostSignaturePolicy::Strict:
      return QStringLiteral("严格校验");
    case GmHostSignaturePolicy::CompatibilityBypass:
      return QStringLiteral("旧版国密适配（降低校验强度）");
  }
  return QStringLiteral("自动（推荐）");
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

QString algorithmModeDisplayText(AlgorithmMode mode) {
  switch (mode) {
    case AlgorithmMode::GmOnly:
      return QStringLiteral("纯国密");
    case AlgorithmMode::StandardOnly:
      return QStringLiteral("标准");
    case AlgorithmMode::Auto:
      return QStringLiteral("自动");
  }
  return QStringLiteral("--");
}

QString algorithmTone(AlgorithmMode mode) {
  switch (mode) {
    case AlgorithmMode::GmOnly:
      return QStringLiteral("gm");
    case AlgorithmMode::StandardOnly:
      return QStringLiteral("standard");
    case AlgorithmMode::Auto:
      return QStringLiteral("auto");
  }
  return QStringLiteral("neutral");
}

void refreshWidgetStyle(QWidget* widget) {
  if (widget == nullptr) {
    return;
  }
  widget->style()->unpolish(widget);
  widget->style()->polish(widget);
  widget->update();
}

QWidget* createProfileCardWidget(const ConnectionProfile& profile, QWidget* parent) {
  auto* card = new QFrame(parent);
  card->setObjectName(QStringLiteral("profileCard"));
  card->setProperty("selected", false);
  card->setProperty("connected", false);

  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(14, 12, 14, 12);
  layout->setSpacing(6);

  auto* title_row = new QHBoxLayout();
  title_row->setContentsMargins(0, 0, 0, 0);
  title_row->setSpacing(8);

  auto* dot = new QLabel(QStringLiteral("●"), card);
  dot->setObjectName(QStringLiteral("profileDot"));
  title_row->addWidget(dot, 0, Qt::AlignVCenter);

  auto* name_label = new QLabel(profile.name, card);
  name_label->setObjectName(QStringLiteral("profileName"));
  title_row->addWidget(name_label, 1);
  layout->addLayout(title_row);

  auto* endpoint_label =
      new QLabel(QStringLiteral("%1:%2").arg(profile.host).arg(profile.port), card);
  endpoint_label->setObjectName(QStringLiteral("profileMeta"));
  layout->addWidget(endpoint_label);

  return card;
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
QLineEdit#profileSearchEdit {
  min-width: 0px;
  max-width: 9999px;
  min-height: 38px;
  max-height: 38px;
  padding: 0 14px;
  margin: 0;
  border-radius: 19px;
  background: #F7F8FA;
}
QLabel#countBadge,
QLabel#footerStatusPill {
  padding: 5px 10px;
  border-radius: 11px;
  background: #F0F3F8;
  border: 1px solid #DDE2EA;
  color: #374151;
  font-weight: 500;
}
QLabel#countBadge,
QLabel#footerStatusPill {
  color: #6B7280;
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
QPushButton:hover {
  background: #F0F3F8;
  color: #111318;
  border-color: #C9D2DE;
}
QPushButton:pressed,
QPushButton:checked {
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
QFrame#workspaceFooter,
QGroupBox,
QTabWidget::pane {
  background: #FFFFFF;
  border: 1px solid #DDE2EA;
  border-radius: 14px;
}
QFrame#workspaceFooter {
  border-radius: 12px;
}
QFrame#leftPanel,
QFrame#terminalPanel {
  background: #FFFFFF;
}
QStackedWidget#leftNavigationStack {
  background: transparent;
  border: none;
}
QWidget#leftNavExpandedPage,
QWidget#leftNavCollapsedPage {
  background: transparent;
}
QToolButton#leftNavExpandButton,
QToolButton#leftNavCollapseButton {
  min-width: 34px;
  min-height: 34px;
  border-radius: 12px;
  border: 1px solid #DDE2EA;
  background: #F0F3F8;
  color: #6B7280;
  font-size: 20px;
  font-weight: 600;
  padding: 0;
}
QToolButton#leftNavExpandButton:hover,
QToolButton#leftNavCollapseButton:hover {
  background: #E8ECF2;
  color: #111318;
  border-color: #C9D2DE;
}
QToolButton#leftNavExpandButton:pressed,
QToolButton#leftNavCollapseButton:pressed {
  background: #DDE2EA;
  color: #0F5F59;
  border-color: #9ED4CD;
}
QLabel#panelTitle,
QLabel#sectionTitle {
  font-size: 18px;
  font-weight: 600;
  color: #111318;
}
QLabel#panelSubtitle,
QLabel#sectionMeta {
  font-size: 12px;
  color: #6B7280;
}
QLabel#profileName {
  font-size: 15px;
  font-weight: 600;
  color: #111318;
}
QLabel#profileMeta {
  color: #6B7280;
  font-size: 12px;
}
QLabel#metricValue {
  color: #111318;
  font-size: 14px;
  font-weight: 600;
}
QLabel#metricCaption {
  color: #6B7280;
  font-size: 12px;
}
QLabel#profileDot {
  color: #22C55E;
  font-size: 12px;
}
QFrame#profileCard {
  background: #FFFFFF;
  border: 1px solid #E8ECF2;
  border-radius: 12px;
}
QFrame#profileCard:hover {
  border-color: #C9D2DE;
  background: #FAFBFC;
}
QFrame#profileCard[selected="true"] {
  border-color: #9ED4CD;
  background: #F6FBFA;
}
QFrame#profileCard[connected="true"] QLabel#profileDot {
  color: #0F766E;
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
QListWidget {
  padding: 4px;
  outline: 0;
}
QListWidget::item {
  color: #111318;
  background: transparent;
}
QListWidget::item:selected {
  color: #111318;
  background: #DDEBFF;
}
QListWidget#profileList::item {
  min-height: 64px;
  padding: 2px;
  border-radius: 12px;
  margin: 3px 0;
  color: transparent;
  background: transparent;
}
QListWidget#profileList::item:hover {
  background: transparent;
}
QListWidget#profileList::item:selected {
  background: transparent;
  color: transparent;
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
  padding: 10px 12px;
  border: 1px solid #DDE2EA;
  border-radius: 12px;
  background: #FFFFFF;
  color: #374151;
  font-weight: 500;
}
QPushButton#quickActionButton {
  min-height: 34px;
  border-radius: 12px;
  padding: 0 14px;
}
QStatusBar {
  min-height: 28px;
  padding: 0 10px;
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

  auto* new_action = new QAction(
      style()->standardIcon(QStyle::SP_FileDialogNewFolder),
      QStringLiteral("新建"),
      this);
  edit_action_ = new QAction(
      style()->standardIcon(QStyle::SP_FileDialogDetailedView),
      QStringLiteral("编辑"),
      this);
  auto* delete_action = new QAction(
      style()->standardIcon(QStyle::SP_TrashIcon),
      QStringLiteral("删除"),
      this);
  auto* connect_action = new QAction(
      style()->standardIcon(QStyle::SP_ArrowForward),
      QStringLiteral("连接"),
      this);
  open_sftp_action_ = new QAction(
      style()->standardIcon(QStyle::SP_DirOpenIcon),
      QStringLiteral("SFTP"),
      this);
  open_audit_action_ = new QAction(
      style()->standardIcon(QStyle::SP_FileDialogContentsView),
      QStringLiteral("审计日志"),
      this);

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
  auto_hostsig_action_ =
      security_menu->addAction(QStringLiteral("国密旧版服务端适配：自动（推荐）"));
  auto_hostsig_action_->setCheckable(true);
  strict_hostsig_action_ =
      security_menu->addAction(QStringLiteral("国密旧版服务端适配：严格校验"));
  strict_hostsig_action_->setCheckable(true);
  compat_hostsig_action_ =
      security_menu->addAction(QStringLiteral("国密旧版服务端适配（降低校验强度）"));
  compat_hostsig_action_->setCheckable(true);
  auto* hostsig_group = new QActionGroup(this);
  hostsig_group->setExclusive(true);
  hostsig_group->addAction(auto_hostsig_action_);
  hostsig_group->addAction(strict_hostsig_action_);
  hostsig_group->addAction(compat_hostsig_action_);
  auto_hostsig_action_->setChecked(true);

  auto* central = new QWidget(this);
  auto* root_layout = new QVBoxLayout(central);
  root_layout->setContentsMargins(12, 10, 12, 12);
  root_layout->setSpacing(12);

  auto* content_row = new QHBoxLayout();
  content_row->setContentsMargins(0, 0, 0, 0);
  content_row->setSpacing(12);
  root_layout->addLayout(content_row, 1);

  main_splitter_ = new QSplitter(Qt::Horizontal, central);
  main_splitter_->setChildrenCollapsible(false);
  content_row->addWidget(main_splitter_, 1);

  left_panel_ = new QFrame(main_splitter_);
  left_panel_->setObjectName(QStringLiteral("leftPanel"));
  left_panel_->setMinimumWidth(230);
  left_panel_->setMaximumWidth(290);

  auto* left_layout = new QVBoxLayout(left_panel_);
  left_layout->setContentsMargins(8, 8, 8, 8);
  left_layout->setSpacing(0);

  left_navigation_stack_ = new QStackedWidget(left_panel_);
  left_navigation_stack_->setObjectName(QStringLiteral("leftNavigationStack"));
  left_layout->addWidget(left_navigation_stack_, 1);

  auto* left_expanded_page = new QWidget(left_navigation_stack_);
  left_expanded_page->setObjectName(QStringLiteral("leftNavExpandedPage"));
  auto* left_expanded_layout = new QVBoxLayout(left_expanded_page);
  left_expanded_layout->setContentsMargins(6, 6, 6, 6);
  left_expanded_layout->setSpacing(12);

  auto* session_header = new QHBoxLayout();
  session_header->setContentsMargins(0, 0, 0, 0);
  session_header->setSpacing(8);
  auto* nav_title = new QLabel(QStringLiteral("主机管理"), left_expanded_page);
  nav_title->setObjectName(QStringLiteral("sectionTitle"));
  session_header->addWidget(nav_title, 1);
  left_nav_collapse_button_ = new QToolButton(left_expanded_page);
  left_nav_collapse_button_->setObjectName(QStringLiteral("leftNavCollapseButton"));
  left_nav_collapse_button_->setText(QStringLiteral("‹"));
  left_nav_collapse_button_->setToolTip(QStringLiteral("收起主机管理"));
  left_nav_collapse_button_->setCursor(Qt::PointingHandCursor);
  left_nav_collapse_button_->setAutoRaise(false);
  left_nav_collapse_button_->setFixedSize(34, 34);
  left_nav_collapse_button_->setVisible(false);
  session_header->addWidget(left_nav_collapse_button_, 0, Qt::AlignRight);
  session_count_label_ = new QLabel(QStringLiteral("0"), left_expanded_page);
  session_count_label_->setObjectName(QStringLiteral("countBadge"));
  session_header->addWidget(session_count_label_, 0, Qt::AlignRight);
  left_expanded_layout->addLayout(session_header);

  auto* nav_subtitle = new QLabel(QStringLiteral("已保存的连接配置"), left_expanded_page);
  nav_subtitle->setObjectName(QStringLiteral("sectionMeta"));
  left_expanded_layout->addWidget(nav_subtitle);

  auto* search_row = new QWidget(left_expanded_page);
  search_row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  search_row->setMinimumHeight(48);
  search_row->setMaximumHeight(48);
  auto* search_row_layout = new QVBoxLayout(search_row);
  search_row_layout->setContentsMargins(0, 4, 0, 6);
  search_row_layout->setSpacing(0);

  search_edit_ = new QLineEdit(search_row);
  search_edit_->setObjectName(QStringLiteral("profileSearchEdit"));
  search_edit_->setClearButtonEnabled(true);
  search_edit_->setPlaceholderText(QStringLiteral("快速搜索会话 / 主机"));
  search_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  search_row_layout->addWidget(search_edit_);
  left_expanded_layout->addWidget(search_row);

  profile_list_ = new QListWidget(left_expanded_page);
  profile_list_->setObjectName(QStringLiteral("profileList"));
  profile_list_->setAlternatingRowColors(false);
  profile_list_->setSelectionMode(QAbstractItemView::SingleSelection);
  profile_list_->setContextMenuPolicy(Qt::CustomContextMenu);
  profile_list_->setMinimumWidth(0);
  left_expanded_layout->addWidget(profile_list_, 1);

  left_navigation_stack_->addWidget(left_expanded_page);

  auto* left_collapsed_page = new QWidget(left_navigation_stack_);
  left_collapsed_page->setObjectName(QStringLiteral("leftNavCollapsedPage"));
  auto* left_collapsed_layout = new QVBoxLayout(left_collapsed_page);
  left_collapsed_layout->setContentsMargins(6, 10, 6, 10);
  left_collapsed_layout->setSpacing(8);

  left_nav_expand_button_ = new QToolButton(left_collapsed_page);
  left_nav_expand_button_->setObjectName(QStringLiteral("leftNavExpandButton"));
  left_nav_expand_button_->setText(QStringLiteral("›"));
  left_nav_expand_button_->setToolTip(QStringLiteral("展开主机管理"));
  left_nav_expand_button_->setCursor(Qt::PointingHandCursor);
  left_nav_expand_button_->setAutoRaise(false);
  left_nav_expand_button_->setFixedSize(34, 34);
  left_collapsed_layout->addWidget(left_nav_expand_button_, 0, Qt::AlignHCenter | Qt::AlignTop);
  left_collapsed_layout->addStretch(1);

  left_navigation_stack_->addWidget(left_collapsed_page);
  left_navigation_stack_->setCurrentWidget(left_expanded_page);

  auto* terminal_panel = new QFrame(main_splitter_);
  terminal_panel->setObjectName(QStringLiteral("terminalPanel"));

  auto* terminal_layout = new QVBoxLayout(terminal_panel);
  terminal_layout->setContentsMargins(14, 14, 14, 14);
  terminal_layout->setSpacing(12);

  auto* terminal_header = new QHBoxLayout();
  terminal_header->setContentsMargins(0, 0, 0, 0);
  terminal_header->setSpacing(8);
  auto* terminal_title = new QLabel(QStringLiteral("终端工作区"), terminal_panel);
  terminal_title->setObjectName(QStringLiteral("sectionTitle"));
  terminal_header->addWidget(terminal_title, 1);
  auto* terminal_meta = new QLabel(QStringLiteral("多标签 SSH 工作区"), terminal_panel);
  terminal_meta->setObjectName(QStringLiteral("sectionMeta"));
  terminal_header->addWidget(terminal_meta, 0, Qt::AlignRight);
  terminal_layout->addLayout(terminal_header);

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
  terminal_tab_bar->setContextMenuPolicy(Qt::CustomContextMenu);
  terminal_layout->addWidget(terminal_tabs_, 1);

  auto* terminal_footer = new QFrame(terminal_panel);
  terminal_footer->setObjectName(QStringLiteral("workspaceFooter"));
  auto* terminal_footer_layout = new QHBoxLayout(terminal_footer);
  terminal_footer_layout->setContentsMargins(12, 10, 12, 10);
  terminal_footer_layout->setSpacing(8);

  connection_status_label_ = new QLabel(QStringLiteral("未连接"), terminal_footer);
  connection_status_label_->setObjectName(QStringLiteral("statusPill"));
  connection_status_label_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  terminal_footer_layout->addWidget(connection_status_label_, 1);

  terminal_layout->addWidget(terminal_footer);

  main_splitter_->addWidget(left_panel_);
  main_splitter_->addWidget(terminal_panel);
  main_splitter_->setStretchFactor(0, 0);
  main_splitter_->setStretchFactor(1, 1);
  main_splitter_->setSizes({260, 1360});

  setCentralWidget(central);
  applyVisualStyle();

  footer_mode_label_ = new QLabel(QStringLiteral("模式 --"), this);
  footer_mode_label_->setObjectName(QStringLiteral("footerStatusPill"));
  statusBar()->addPermanentWidget(footer_mode_label_);

  footer_sessions_label_ = new QLabel(QStringLiteral("会话 0"), this);
  footer_sessions_label_->setObjectName(QStringLiteral("footerStatusPill"));
  statusBar()->addPermanentWidget(footer_sessions_label_);

  statusBar()->showMessage(
      legacy_ssh_resolution.path.isEmpty()
          ? QStringLiteral("就绪（SSH 引擎来源：%1）").arg(ssh_resolution.source)
          : QStringLiteral("就绪（主引擎：%1；旧版国密引擎：%2）")
                .arg(ssh_resolution.source, legacy_ssh_resolution.source));

  connect(profile_list_, &QListWidget::currentRowChanged, this, &MainWindow::onProfileSelected);
  connect(profile_list_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem*) {
    onConnect();
  });
  connect(profile_list_, &QListWidget::customContextMenuRequested, this, &MainWindow::showProfileContextMenu);
  connect(new_action, &QAction::triggered, this, &MainWindow::onNewProfile);
  connect(edit_action_, &QAction::triggered, this, &MainWindow::onEditProfile);
  connect(delete_action, &QAction::triggered, this, &MainWindow::onDeleteProfile);
  connect(connect_action, &QAction::triggered, this, &MainWindow::onConnect);
  connect(open_sftp_action_, &QAction::triggered, this, &MainWindow::onOpenSftpTool);
  connect(open_audit_action_, &QAction::triggered, this, &MainWindow::onOpenAuditLog);
  connect(auto_hostsig_action_, &QAction::triggered, this, [this]() {
    applyGmHostSignaturePolicy(GmHostSignaturePolicy::Auto);
  });
  connect(strict_hostsig_action_, &QAction::triggered, this, [this]() {
    applyGmHostSignaturePolicy(GmHostSignaturePolicy::Strict);
  });
  connect(compat_hostsig_action_, &QAction::triggered, this, [this]() {
    applyGmHostSignaturePolicy(GmHostSignaturePolicy::CompatibilityBypass);
  });

  connect(search_edit_, &QLineEdit::textChanged, this, &MainWindow::applyProfileFilter);
  connect(left_nav_expand_button_, &QToolButton::clicked, this, [this]() {
    navigation_forced_expanded_ = true;
    updatePaneLayoutForSessionState();
  });
  connect(left_nav_collapse_button_, &QToolButton::clicked, this, [this]() {
    navigation_forced_expanded_ = false;
    updatePaneLayoutForSessionState();
  });

  connect(terminal_tabs_, &QTabWidget::currentChanged, this, [this](int) {
    updateActiveTerminalStatus();
    if (sftp_window_ != nullptr && sftp_window_->isVisible()) {
      syncSftpPanelToCurrentTerminal();
    }
    if (auto* session = currentTerminalSession()) {
      QTimer::singleShot(0, session, [session]() {
        session->activateInputFocus();
      });
    }
  });
  connect(
      terminal_tab_bar,
      &QTabBar::customContextMenuRequested,
      this,
      &MainWindow::showTerminalTabContextMenu);

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

  const auto saved_policy =
      settings.value(QStringLiteral("security/gm_hostsig_policy"), QStringLiteral("auto")).toString();
  const auto policy =
      saved_policy == QStringLiteral("strict")
          ? GmHostSignaturePolicy::Strict
          : (saved_policy == QStringLiteral("compat")
                 ? GmHostSignaturePolicy::CompatibilityBypass
                 : GmHostSignaturePolicy::Auto);
  if (auto_hostsig_action_ != nullptr && strict_hostsig_action_ != nullptr &&
      compat_hostsig_action_ != nullptr) {
    const QSignalBlocker block_auto(auto_hostsig_action_);
    const QSignalBlocker block_strict(strict_hostsig_action_);
    const QSignalBlocker block_compat(compat_hostsig_action_);
    auto_hostsig_action_->setChecked(policy == GmHostSignaturePolicy::Auto);
    strict_hostsig_action_->setChecked(policy == GmHostSignaturePolicy::Strict);
    compat_hostsig_action_->setChecked(policy == GmHostSignaturePolicy::CompatibilityBypass);
  }
  applyGmHostSignaturePolicy(policy);
}

void MainWindow::persistUiState() const {
  QSettings settings;
  settings.setValue(QStringLiteral("ui/window_geometry"), saveGeometry());

  if (main_splitter_ != nullptr) {
    settings.setValue(QStringLiteral("ui/main_splitter_state"), main_splitter_->saveState());
  }
  const auto policy = ssh_adapter_.gmHostSignaturePolicy();
  settings.setValue(
      QStringLiteral("security/gm_hostsig_policy"),
      policy == GmHostSignaturePolicy::Strict
          ? QStringLiteral("strict")
          : (policy == GmHostSignaturePolicy::CompatibilityBypass
                 ? QStringLiteral("compat")
                 : QStringLiteral("auto")));
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
  updatePaneLayoutForSessionState();
  if (sftp_window_ != nullptr && sftp_window_->isVisible()) {
    syncSftpPanelToCurrentTerminal();
  }
}

void MainWindow::refreshProfileCardStates() {
  if (profile_list_ == nullptr) {
    return;
  }

  QStringList connected_profiles;
  if (terminal_tabs_ != nullptr) {
    for (int i = 0; i < terminal_tabs_->count(); ++i) {
      if (auto* session = qobject_cast<TerminalSessionWidget*>(terminal_tabs_->widget(i))) {
        connected_profiles.push_back(session->profile().name);
      }
    }
  }

  const int current_row = profile_list_->currentRow();
  int visible_count = 0;
  for (int i = 0; i < profile_list_->count(); ++i) {
    auto* item = profile_list_->item(i);
    if (item == nullptr) {
      continue;
    }
    if (!item->isHidden()) {
      ++visible_count;
    }

    if (auto* card = profile_list_->itemWidget(item)) {
      card->setProperty("selected", i == current_row);
      card->setProperty(
          "connected",
          i < profiles_.size() && connected_profiles.contains(profiles_[i].name));
      refreshWidgetStyle(card);
    }
  }

  if (session_count_label_ != nullptr) {
    session_count_label_->setText(QStringLiteral("%1 / %2").arg(visible_count).arg(profiles_.size()));
  }
}

void MainWindow::refreshContextPanels() {
  const auto selected = selectedProfile();
  auto* current_session = currentTerminalSession();
  const auto* profile = current_session != nullptr ? &current_session->profile()
                                                   : (selected.has_value() ? &selected.value()
                                                                           : nullptr);
  const auto mode_text = profile != nullptr ? algorithmModeDisplayText(profile->algorithm_mode)
                                            : QStringLiteral("--");
  const int session_count = terminal_tabs_ != nullptr ? terminal_tabs_->count() : 0;
  if (footer_mode_label_ != nullptr) {
    footer_mode_label_->setText(QStringLiteral("模式 %1").arg(mode_text));
  }
  if (footer_sessions_label_ != nullptr) {
    footer_sessions_label_->setText(QStringLiteral("会话 %1").arg(session_count));
  }
}

void MainWindow::showProfileContextMenu(const QPoint& pos) {
  if (profile_list_ == nullptr) {
    return;
  }

  auto* item = profile_list_->itemAt(pos);
  if (item != nullptr) {
    profile_list_->setCurrentItem(item);
  }

  QMenu menu(this);
  auto* new_action = menu.addAction(QStringLiteral("新建主机"));

  QAction* connect_action = nullptr;
  QAction* sftp_action = nullptr;
  QAction* edit_action = nullptr;
  QAction* delete_action = nullptr;

  if (item != nullptr) {
    menu.addSeparator();
    connect_action = menu.addAction(QStringLiteral("连接"));
    sftp_action = menu.addAction(QStringLiteral("打开 SFTP"));
    menu.addSeparator();
    edit_action = menu.addAction(QStringLiteral("编辑"));
    delete_action = menu.addAction(QStringLiteral("删除"));
  }

  menu.addSeparator();
  auto* audit_action = menu.addAction(QStringLiteral("查看审计日志"));

  const auto* chosen = menu.exec(profile_list_->viewport()->mapToGlobal(pos));
  if (chosen == nullptr) {
    return;
  }

  if (chosen == new_action) {
    QTimer::singleShot(0, this, [this]() { onNewProfile(); });
  } else if (chosen == connect_action) {
    QTimer::singleShot(0, this, [this]() { onConnect(); });
  } else if (chosen == sftp_action) {
    QTimer::singleShot(0, this, [this]() { onOpenSftpTool(); });
  } else if (chosen == edit_action) {
    QTimer::singleShot(0, this, [this]() { onEditProfile(); });
  } else if (chosen == delete_action) {
    QTimer::singleShot(0, this, [this]() { onDeleteProfile(); });
  } else if (chosen == audit_action) {
    QTimer::singleShot(0, this, [this]() { onOpenAuditLog(); });
  }
}

void MainWindow::showTerminalTabContextMenu(const QPoint& pos) {
  if (terminal_tabs_ == nullptr) {
    return;
  }

  auto* tab_bar = terminal_tabs_->tabBar();
  if (tab_bar == nullptr) {
    return;
  }

  const int idx = tab_bar->tabAt(pos);
  if (idx < 0) {
    return;
  }

  terminal_tabs_->setCurrentIndex(idx);

  QMenu menu(this);
  auto* duplicate_action = menu.addAction(QStringLiteral("复制会话"));
  auto* close_action = menu.addAction(QStringLiteral("关闭会话"));
  auto* close_others_action = menu.addAction(QStringLiteral("关闭其他会话"));
  menu.addSeparator();
  auto* copy_content_action = menu.addAction(QStringLiteral("复制当前内容"));
  auto* export_action = menu.addAction(QStringLiteral("导出会话内容…"));
  auto* clear_action = menu.addAction(QStringLiteral("清屏"));
  menu.addSeparator();
  auto* open_sftp_action = menu.addAction(QStringLiteral("在 SFTP 中打开"));

  if (terminal_tabs_->count() <= 1) {
    close_others_action->setEnabled(false);
  }

  const auto* chosen = menu.exec(tab_bar->mapToGlobal(pos));
  if (chosen == nullptr) {
    return;
  }

  if (chosen == duplicate_action) {
    duplicateTerminalSession(idx);
  } else if (chosen == close_action) {
    closeTerminalTab(idx);
  } else if (chosen == close_others_action) {
    for (int i = terminal_tabs_->count() - 1; i >= 0; --i) {
      if (i != idx) {
        closeTerminalTab(i);
      }
    }
  } else if (chosen == copy_content_action) {
    if (auto* session = terminalSessionAtTab(idx)) {
      if (auto* clipboard = QGuiApplication::clipboard(); clipboard != nullptr) {
        clipboard->setText(session->terminalText());
      }
    }
  } else if (chosen == export_action) {
    exportTerminalSessionContent(idx);
  } else if (chosen == clear_action) {
    if (auto* session = terminalSessionAtTab(idx)) {
      session->requestClearScreen();
    }
  } else if (chosen == open_sftp_action) {
    if (terminal_tabs_ != nullptr) {
      terminal_tabs_->setCurrentIndex(idx);
      onOpenSftpTool();
    }
  }
}

TerminalSessionWidget* MainWindow::terminalSessionAtTab(int idx) const {
  if (terminal_tabs_ == nullptr || idx < 0 || idx >= terminal_tabs_->count()) {
    return nullptr;
  }
  return qobject_cast<TerminalSessionWidget*>(terminal_tabs_->widget(idx));
}

void MainWindow::duplicateTerminalSession(int idx) {
  auto* session = terminalSessionAtTab(idx);
  if (session == nullptr) {
    return;
  }

  auto profile = session->profile();
  auto secrets = session->secrets();
  startTerminalSession(profile, secrets);
}

void MainWindow::exportTerminalSessionContent(int idx) {
  auto* session = terminalSessionAtTab(idx);
  if (session == nullptr) {
    return;
  }

  const auto default_path =
      QDir::home().filePath(QStringLiteral("%1-session.txt").arg(session->sessionName()));
  const auto path = QFileDialog::getSaveFileName(
      this,
      QStringLiteral("导出会话内容"),
      default_path,
      QStringLiteral("Text Files (*.txt);;All Files (*)"));
  if (path.isEmpty()) {
    return;
  }

  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
    QMessageBox::warning(
        this,
        QStringLiteral("导出失败"),
        QStringLiteral("无法写入文件：%1").arg(file.errorString()));
    return;
  }

  file.write(session->terminalText().toUtf8());
  file.close();
  statusBar()->showMessage(QStringLiteral("会话内容已导出"), 2500);
}

bool MainWindow::startTerminalSession(ConnectionProfile profile, SessionSecrets secrets) {
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
    return false;
  }

  auto* session = new TerminalSessionWidget(
      profile.name,
      profile,
      secrets,
      launch_plan,
      &audit_logger_,
      &ssh_adapter_,
      terminal_tabs_);
  const auto connected_status =
      QStringLiteral("已连接：%1@%2:%3  ｜  连接方式：%4")
          .arg(profile.username)
          .arg(profile.host)
          .arg(profile.port)
          .arg(connectionProtocolText(profile, launch_plan));
  session->setProperty(kTerminalStatusProperty, connected_status);
  const auto tab_idx = terminal_tabs_->addTab(session, profile.name);
  terminal_tabs_->setCurrentIndex(tab_idx);
  QTimer::singleShot(0, session, [session]() {
    session->activateInputFocus();
  });
  updatePaneLayoutForSessionState();

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
  return true;
}

void MainWindow::updatePaneLayoutForSessionState() {
  if (main_splitter_ == nullptr || terminal_tabs_ == nullptr) {
    return;
  }

  const bool has_active_session = terminal_tabs_->count() > 0;
  if (!has_active_session) {
    navigation_forced_expanded_ = false;
  }
  const bool should_collapse_navigation =
      has_active_session && !navigation_forced_expanded_;

  if (left_navigation_stack_ != nullptr) {
    left_navigation_stack_->setCurrentIndex(should_collapse_navigation ? 1 : 0);
  }
  if (left_nav_collapse_button_ != nullptr) {
    left_nav_collapse_button_->setVisible(has_active_session && !should_collapse_navigation);
  }
  if (left_panel_ != nullptr) {
    left_panel_->setMinimumWidth(should_collapse_navigation ? 76 : 230);
    left_panel_->setMaximumWidth(should_collapse_navigation ? 92 : 290);
  }
  auto sizes = main_splitter_->sizes();
  if (sizes.size() < 2) {
    return;
  }

  if (should_collapse_navigation && !auto_collapsed_navigation_) {
    sizes[0] = 84;
    sizes[1] = std::max(sizes[1], 1120);
    main_splitter_->setSizes(sizes);
    auto_collapsed_navigation_ = true;
    return;
  }

  if (!should_collapse_navigation && auto_collapsed_navigation_) {
    sizes[0] = 260;
    sizes[1] = std::max(sizes[1], 1080);
    main_splitter_->setSizes(sizes);
    auto_collapsed_navigation_ = false;
  }
}

void MainWindow::reloadProfiles() {
  QString error;
  profiles_ = profile_repository_.loadAll(&error);

  profile_list_->clear();
  for (const auto& profile : profiles_) {
    auto* item = new QListWidgetItem(profile_list_);
    item->setSizeHint(QSize(0, 74));
    item->setToolTip(QStringLiteral("%1@%2:%3").arg(profile.username).arg(profile.host).arg(profile.port));
    profile_list_->setItemWidget(item, createProfileCardWidget(profile, profile_list_));
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

  refreshProfileCardStates();
  refreshContextPanels();
  updatePaneLayoutForSessionState();
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
                         profile.host.contains(query, Qt::CaseInsensitive) ||
                         profile.username.contains(query, Qt::CaseInsensitive);
    item->setHidden(!visible);
  }

  auto* current_item = profile_list_->currentItem();
  if (current_item == nullptr || current_item->isHidden()) {
    bool found_visible = false;
    for (int i = 0; i < profile_list_->count(); ++i) {
      auto* item = profile_list_->item(i);
      if (item != nullptr && !item->isHidden()) {
        profile_list_->setCurrentRow(i);
        found_visible = true;
        break;
      }
    }
    if (!found_visible) {
      profile_list_->setCurrentRow(-1);
    }
  }

  refreshProfileCardStates();
  refreshContextPanels();
}

void MainWindow::updateConnectionStatus(const QString& text) {
  if (connection_status_label_ != nullptr) {
    connection_status_label_->setText(text);
  }
  refreshContextPanels();
}

void MainWindow::applyVisualStyle() {
  qApp->setStyleSheet(mainWindowStyleSheet());
}

void MainWindow::applyGmHostSignaturePolicy(GmHostSignaturePolicy policy) {
  const bool changed = ssh_adapter_.gmHostSignaturePolicy() != policy;
  ssh_adapter_.setGmHostSignaturePolicy(policy);

  if (!changed) {
    return;
  }

  const auto policy_text = gmHostSignaturePolicyText(policy);
  statusBar()->showMessage(
      QStringLiteral("国密主机签名校验已切换为：%1").arg(policy_text),
      3200);
  updateConnectionStatus(QStringLiteral("国密主机签名校验：%1").arg(policy_text));
  audit_logger_.logEvent(
      QStringLiteral("hostsig_policy_changed"),
      QJsonObject{
          {QStringLiteral("policy"),
           policy == GmHostSignaturePolicy::Strict
               ? QStringLiteral("strict")
               : (policy == GmHostSignaturePolicy::CompatibilityBypass
                      ? QStringLiteral("compat")
                      : QStringLiteral("auto"))},
      });
}

void MainWindow::onProfileSelected(int row) {
  if (row < 0 || row >= profiles_.size()) {
    refreshProfileCardStates();
    refreshContextPanels();
    return;
  }

  const auto& profile = profiles_[row];
  refreshProfileCardStates();
  updateConnectionStatus(
      QStringLiteral("已选中会话：%1 (%2@%3:%4)")
          .arg(profile.name)
          .arg(profile.username)
          .arg(profile.host)
          .arg(profile.port));
}

void MainWindow::updateActiveTerminalStatus() {
  if (terminal_tabs_ == nullptr || terminal_tabs_->count() == 0) {
    refreshProfileCardStates();
    updatePaneLayoutForSessionState();
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
    refreshProfileCardStates();
    updatePaneLayoutForSessionState();
    updateConnectionStatus(QStringLiteral("未连接"));
    return;
  }

  const auto status_text = current->property(kTerminalStatusProperty).toString().trimmed();
  if (status_text.isEmpty()) {
    refreshProfileCardStates();
    updatePaneLayoutForSessionState();
    updateConnectionStatus(QStringLiteral("当前终端标签无连接状态"));
    return;
  }
  refreshProfileCardStates();
  updatePaneLayoutForSessionState();
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

  if (profile.save_credential && !secrets.password.isEmpty()) {
    const auto saved = credential_store_.savePassword(profile.name, secrets.password);
    if (!saved.ok) {
      audit_logger_.logEvent(
          QStringLiteral("credential_save_failed"),
          QJsonObject{{QStringLiteral("profile"), profile.name},
                      {QStringLiteral("error"), saved.error}});
    }
  }

  startTerminalSession(profile, secrets);
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
