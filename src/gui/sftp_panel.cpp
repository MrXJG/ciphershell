#include "gui/sftp_panel.h"

#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonObject>
#include <QKeyEvent>
#include <QMessageBox>
#include <QRegularExpression>
#include <QShowEvent>
#include <QSplitter>
#include <QTextCursor>
#include <QVBoxLayout>

#include <optional>

namespace gmssh {
namespace {

constexpr int kPathRole = Qt::UserRole;
constexpr int kIsDirectoryRole = Qt::UserRole + 1;
constexpr int kIsRegularFileRole = Qt::UserRole + 2;
constexpr qsizetype kMaxLogLines = 800;

QString quoteSftpPath(const QString& path) {
  auto escaped = path.trimmed();
  escaped.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
  escaped.replace(QStringLiteral("\""), QStringLiteral("\\\""));
  return QStringLiteral("\"%1\"").arg(escaped);
}

QString cleanRemotePath(QString path) {
  path = path.trimmed();
  if (path.isEmpty()) {
    return QStringLiteral(".");
  }
  while (path.size() > 1 && path.endsWith(QChar::fromLatin1('/'))) {
    path.chop(1);
  }
  return path;
}

QString joinRemotePath(const QString& directory, const QString& name) {
  const auto trimmed_name = name.trimmed();
  if (trimmed_name.isEmpty()) {
    return cleanRemotePath(directory);
  }
  if (trimmed_name.startsWith(QChar::fromLatin1('/'))) {
    return cleanRemotePath(trimmed_name);
  }

  const auto dir = cleanRemotePath(directory);
  if (dir == QStringLiteral(".")) {
    return trimmed_name;
  }
  if (dir == QStringLiteral("/")) {
    return QStringLiteral("/%1").arg(trimmed_name);
  }
  return QStringLiteral("%1/%2").arg(dir, trimmed_name);
}

QString parentRemotePath(const QString& directory) {
  auto dir = cleanRemotePath(directory);
  if (dir == QStringLiteral(".") || dir == QStringLiteral("/")) {
    return dir;
  }

  const auto slash = dir.lastIndexOf(QChar::fromLatin1('/'));
  if (slash < 0) {
    return QStringLiteral(".");
  }
  if (slash == 0) {
    return QStringLiteral("/");
  }
  return dir.left(slash);
}

QString fileNameFromRemotePath(QString path) {
  path = cleanRemotePath(path);
  if (path == QStringLiteral("/") || path == QStringLiteral(".")) {
    return path;
  }
  const auto slash = path.lastIndexOf(QChar::fromLatin1('/'));
  return slash < 0 ? path : path.mid(slash + 1);
}

bool isOctalMode(const QString& mode) {
  static const QRegularExpression kPattern(QStringLiteral("^[0-7]{3,4}$"));
  return kPattern.match(mode.trimmed()).hasMatch();
}

QString algorithmModeZh(AlgorithmMode mode) {
  switch (mode) {
    case AlgorithmMode::GmOnly:
      return QStringLiteral("国密");
    case AlgorithmMode::StandardOnly:
      return QStringLiteral("常规");
    case AlgorithmMode::Auto:
      return QStringLiteral("自动");
  }
  return QStringLiteral("未知");
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
  if (reason == QStringLiteral("gm_probe_runtime_incompatible")) {
    return QStringLiteral("国密协商后出现运行时兼容问题");
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

QString displaySafeDiagnostics(QString text) {
  text.replace(
      QStringLiteral("ecgm-sm2-sm3 host signature verify bypass enabled for compatibility"),
      QStringLiteral("ecgm-sm2-sm3 旧版国密主机签名适配已启用"));
  return text.replace(
      QStringLiteral("ecgm-sm2-sm3 legacy GM host-signature adaptation enabled"),
      QStringLiteral("ecgm-sm2-sm3 旧版国密主机签名适配已启用"));
}

QString stderrTailForAudit(QString text) {
  text = text.trimmed();
  constexpr qsizetype kMaxAuditChars = 700;
  if (text.size() > kMaxAuditChars) {
    return text.right(kMaxAuditChars);
  }
  return text;
}

QString failureHint(const SftpExecutionResult& result) {
  const auto combined = QStringLiteral("%1\n%2").arg(result.error, result.std_err);
  if (combined.contains(QStringLiteral("/tmp/gmssh-engine-install/bin/ssh"),
                        Qt::CaseInsensitive)) {
    return QStringLiteral(
        "检测到旧 SFTP 二进制仍在调用硬编码 SSH 路径。请重新启动最新构建的 GUI 后再试。");
  }
  if (combined.contains(QStringLiteral("Permission denied"), Qt::CaseInsensitive) ||
      combined.contains(QStringLiteral("Authentication failed"), Qt::CaseInsensitive)) {
    return QStringLiteral("认证失败。请确认当前会话密码/密钥仍有效，并重新连接后再打开 SFTP。");
  }
  if (combined.contains(QStringLiteral("subsystem request failed"), Qt::CaseInsensitive) ||
      combined.contains(QStringLiteral("sftp-server"), Qt::CaseInsensitive)) {
    return QStringLiteral("服务端可能未启用 SFTP 子系统，请检查 sshd_config 的 Subsystem sftp 配置。");
  }
  if (combined.contains(QStringLiteral("No such file"), Qt::CaseInsensitive) ||
      combined.contains(QStringLiteral("not found"), Qt::CaseInsensitive)) {
    return QStringLiteral("路径不存在。请确认当前目录、选中文件和本地保存目录是否正确。");
  }
  if (combined.contains(QStringLiteral("Connection closed"), Qt::CaseInsensitive)) {
    return QStringLiteral("连接被服务端关闭。若终端可连，请优先检查服务端 SFTP 子系统或认证方式限制。");
  }
  if (result.timed_out) {
    return QStringLiteral("SFTP 操作超时。请确认网络连通性、服务端 SFTP 子系统和目标路径是否可访问。");
  }
  return {};
}

struct RemoteEntry {
  QString permissions;
  QString name;
  bool is_directory = false;
  bool is_regular_file = false;
  QString display;
};

std::optional<RemoteEntry> parseListingLine(const QString& line) {
  const auto trimmed = line.trimmed();
  if (trimmed.isEmpty() || trimmed.startsWith(QStringLiteral("sftp>"))) {
    return std::nullopt;
  }
  if (trimmed.startsWith(QStringLiteral("Connected to ")) ||
      trimmed.startsWith(QStringLiteral("Changing to: "))) {
    return std::nullopt;
  }

  const auto parts = trimmed.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
  if (parts.size() < 9) {
    return std::nullopt;
  }

  const auto permissions = parts.at(0);
  if (permissions.isEmpty()) {
    return std::nullopt;
  }
  const auto type = permissions.at(0);
  if (type != QChar::fromLatin1('d') && type != QChar::fromLatin1('-') &&
      type != QChar::fromLatin1('l')) {
    return std::nullopt;
  }

  const auto name = parts.mid(8).join(QStringLiteral(" "));
  if (name == QStringLiteral(".") || name == QStringLiteral("..")) {
    return std::nullopt;
  }

  RemoteEntry entry;
  entry.permissions = permissions;
  entry.name = name;
  entry.is_directory = type == QChar::fromLatin1('d');
  entry.is_regular_file = type == QChar::fromLatin1('-');
  const auto kind = entry.is_directory
                        ? QStringLiteral("[目录] ")
                        : (entry.is_regular_file ? QStringLiteral("      ")
                                                 : QStringLiteral("[链接] "));
  entry.display = QStringLiteral("%1  %2%3")
                      .arg(permissions, kind, name);
  return entry;
}

}  // namespace

SftpPanel::SftpPanel(QWidget* parent) : QWidget(parent) {
  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(8, 8, 8, 8);
  layout->setSpacing(8);

  status_label_ = new QLabel(QStringLiteral("未绑定 SSH 会话。请先连接主机。"), this);
  status_label_->setWordWrap(true);
  layout->addWidget(status_label_);

  auto* splitter = new QSplitter(Qt::Horizontal, this);

  auto* browser_group = new QGroupBox(QStringLiteral("远端目录"), splitter);
  auto* browser_layout = new QVBoxLayout(browser_group);
  browser_layout->setSpacing(8);
  auto* directory_row = new QHBoxLayout();
  directory_row->setContentsMargins(0, 0, 0, 0);
  directory_row->setSpacing(6);
  remote_dir_edit_ = new QLineEdit(browser_group);
  remote_dir_edit_->setPlaceholderText(QStringLiteral("例如 /root；回车刷新"));
  remote_dir_edit_->installEventFilter(this);
  parent_button_ = new QPushButton(QStringLiteral("上级"), browser_group);
  refresh_button_ = new QPushButton(QStringLiteral("刷新"), browser_group);
  directory_row->addWidget(remote_dir_edit_, 1);
  directory_row->addWidget(parent_button_);
  directory_row->addWidget(refresh_button_);
  browser_layout->addLayout(directory_row);

  remote_list_ = new QListWidget(browser_group);
  remote_list_->setAlternatingRowColors(true);
  remote_list_->setSelectionMode(QAbstractItemView::SingleSelection);
  browser_layout->addWidget(remote_list_, 1);

  auto* operations_group = new QGroupBox(QStringLiteral("当前选择与操作"), splitter);
  auto* operations_layout = new QVBoxLayout(operations_group);
  operations_layout->setSpacing(8);

  auto* selected_form = new QFormLayout();
  selected_remote_edit_ = new QLineEdit(operations_group);
  selected_remote_edit_->setPlaceholderText(QStringLiteral("点击左侧远端列表自动填充，也可手动填写"));
  selected_form->addRow(QStringLiteral("远端对象"), selected_remote_edit_);
  operations_layout->addLayout(selected_form);

  auto* upload_group = new QGroupBox(QStringLiteral("上传到当前远端目录"), operations_group);
  auto* upload_layout = new QHBoxLayout(upload_group);
  upload_layout->setSpacing(6);
  upload_file_edit_ = new QLineEdit(upload_group);
  upload_file_edit_->setPlaceholderText(QStringLiteral("选择本地文件"));
  choose_upload_button_ = new QPushButton(QStringLiteral("选择"), upload_group);
  upload_button_ = new QPushButton(QStringLiteral("上传"), upload_group);
  upload_layout->addWidget(upload_file_edit_, 1);
  upload_layout->addWidget(choose_upload_button_);
  upload_layout->addWidget(upload_button_);
  operations_layout->addWidget(upload_group);

  auto* download_group = new QGroupBox(QStringLiteral("下载选中远端文件"), operations_group);
  auto* download_layout = new QHBoxLayout(download_group);
  download_layout->setSpacing(6);
  download_dir_edit_ = new QLineEdit(download_group);
  download_dir_edit_->setPlaceholderText(QStringLiteral("选择本地保存目录"));
  choose_download_dir_button_ = new QPushButton(QStringLiteral("选择"), download_group);
  download_button_ = new QPushButton(QStringLiteral("下载"), download_group);
  download_layout->addWidget(download_dir_edit_, 1);
  download_layout->addWidget(choose_download_dir_button_);
  download_layout->addWidget(download_button_);
  operations_layout->addWidget(download_group);

  auto* file_row = new QHBoxLayout();
  file_row->setContentsMargins(0, 0, 0, 0);
  file_row->setSpacing(6);
  rename_button_ = new QPushButton(QStringLiteral("重命名"), operations_group);
  chmod_button_ = new QPushButton(QStringLiteral("改权限"), operations_group);
  delete_file_button_ = new QPushButton(QStringLiteral("删除文件"), operations_group);
  delete_dir_button_ = new QPushButton(QStringLiteral("删除空目录"), operations_group);
  file_row->addWidget(rename_button_);
  file_row->addWidget(chmod_button_);
  file_row->addWidget(delete_file_button_);
  file_row->addWidget(delete_dir_button_);
  operations_layout->addLayout(file_row);

  mkdir_button_ = new QPushButton(QStringLiteral("在当前目录新建子目录"), operations_group);
  operations_layout->addWidget(mkdir_button_);
  operations_layout->addStretch(1);

  splitter->addWidget(browser_group);
  splitter->addWidget(operations_group);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);
  layout->addWidget(splitter, 3);

  output_view_ = new QPlainTextEdit(this);
  output_view_->setReadOnly(true);
  output_view_->setPlaceholderText(QStringLiteral("SFTP 操作日志会显示在这里。成功操作会降噪，失败时显示完整诊断。"));
  layout->addWidget(output_view_, 2);

  connect(refresh_button_, &QPushButton::clicked, this, &SftpPanel::refreshRemoteList);
  connect(parent_button_, &QPushButton::clicked, this, &SftpPanel::enterParentDirectory);
  connect(remote_list_, &QListWidget::itemClicked, this, &SftpPanel::syncSelectedRemote);
  connect(remote_list_, &QListWidget::itemDoubleClicked, this, &SftpPanel::enterSelectedDirectory);
  connect(choose_upload_button_, &QPushButton::clicked, this, &SftpPanel::chooseUploadFile);
  connect(upload_button_, &QPushButton::clicked, this, &SftpPanel::uploadToCurrentDirectory);
  connect(choose_download_dir_button_, &QPushButton::clicked, this, &SftpPanel::chooseDownloadDirectory);
  connect(download_button_, &QPushButton::clicked, this, &SftpPanel::downloadSelectedRemote);
  connect(rename_button_, &QPushButton::clicked, this, &SftpPanel::renameSelectedRemote);
  connect(mkdir_button_, &QPushButton::clicked, this, &SftpPanel::createDirectory);
  connect(delete_file_button_, &QPushButton::clicked, this, &SftpPanel::deleteSelectedFile);
  connect(delete_dir_button_, &QPushButton::clicked, this, &SftpPanel::deleteSelectedDirectory);
  connect(chmod_button_, &QPushButton::clicked, this, &SftpPanel::chmodSelectedRemote);

  for (auto* button : findChildren<QPushButton*>()) {
    button->setAutoDefault(false);
    button->setDefault(false);
    button->setMinimumWidth(0);
  }
}

void SftpPanel::setEngineAdapter(const SshEngineAdapter* adapter) {
  adapter_ = adapter;
}

void SftpPanel::setAuditLogger(AuditLogger* logger) {
  audit_logger_ = logger;
}

void SftpPanel::setContext(ConnectionProfile profile, SessionSecrets secrets) {
  const auto previous_context = context_key_;
  const auto next_context = contextKey(profile);
  profile_ = std::move(profile);
  secrets_ = std::move(secrets);
  has_context_ = true;
  context_key_ = next_context;

  const bool context_changed = previous_context != next_context;
  if (context_changed || current_remote_dir_.trimmed().isEmpty()) {
    setCurrentRemoteDir(profile_.sftp_root.trimmed().isEmpty()
                            ? QStringLiteral(".")
                            : profile_.sftp_root);
    selected_remote_edit_->clear();
    remote_list_->clear();
  }

  pending_initial_refresh_ = context_changed && remote_list_->count() == 0;
  updateStatusLabel();
}

void SftpPanel::clearContext() {
  profile_ = ConnectionProfile{};
  secrets_ = SessionSecrets{};
  has_context_ = false;
  pending_initial_refresh_ = false;
  context_key_.clear();
  current_remote_dir_.clear();
  remote_dir_edit_->clear();
  selected_remote_edit_->clear();
  remote_list_->clear();
  updateStatusLabel();
}

void SftpPanel::refreshPendingInitial() {
  if (pending_initial_refresh_ && has_context_) {
    pending_initial_refresh_ = false;
    refreshRemoteList();
  }
}

void SftpPanel::showEvent(QShowEvent* event) {
  QWidget::showEvent(event);
  refreshPendingInitial();
}

bool SftpPanel::eventFilter(QObject* watched, QEvent* event) {
  if (watched == remote_dir_edit_ && event->type() == QEvent::KeyPress) {
    const auto* key_event = static_cast<QKeyEvent*>(event);
    if (key_event->key() == Qt::Key_Return || key_event->key() == Qt::Key_Enter) {
      refreshRemoteList();
      return true;
    }
  }
  return QWidget::eventFilter(watched, event);
}

QString SftpPanel::contextKey(const ConnectionProfile& profile) const {
  return QStringLiteral("%1|%2|%3|%4")
      .arg(profile.name, profile.host)
      .arg(profile.port)
      .arg(profile.username);
}

void SftpPanel::setCurrentRemoteDir(QString directory) {
  current_remote_dir_ = cleanRemotePath(std::move(directory));
  if (remote_dir_edit_ != nullptr && remote_dir_edit_->text() != current_remote_dir_) {
    remote_dir_edit_->setText(current_remote_dir_);
  }
}

QString SftpPanel::currentRemoteDir() const {
  return cleanRemotePath(current_remote_dir_);
}

QString SftpPanel::selectedRemotePath() const {
  return cleanRemotePath(selected_remote_edit_->text());
}

void SftpPanel::refreshRemoteList() {
  refreshRemoteListFor(remote_dir_edit_->text());
}

void SftpPanel::refreshRemoteListFor(QString directory) {
  directory = cleanRemotePath(std::move(directory));
  const auto previous_directory = currentRemoteDir();
  if (remote_dir_edit_->text() != directory) {
    remote_dir_edit_->setText(directory);
  }

  const auto result = runBatch(
      {QStringLiteral("ls -la %1").arg(quoteSftpPath(directory))},
      QStringLiteral("sftp_list"));
  if (!result.ok) {
    setCurrentRemoteDir(previous_directory);
    return;
  }

  setCurrentRemoteDir(directory);
  remote_list_->clear();
  selected_remote_edit_->clear();

  for (const auto& line : result.std_out.split(QChar::fromLatin1('\n'))) {
    const auto parsed = parseListingLine(line);
    if (!parsed.has_value()) {
      continue;
    }

    const auto remote_path = joinRemotePath(directory, parsed->name);
    auto* item = new QListWidgetItem(parsed->display, remote_list_);
    item->setData(kPathRole, remote_path);
    item->setData(kIsDirectoryRole, parsed->is_directory);
    item->setData(kIsRegularFileRole, parsed->is_regular_file);
  }

  prependLogBlock(
      QStringLiteral("[完成] 已刷新远端目录：%1（%2 项）")
          .arg(directory)
          .arg(remote_list_->count()));
  updateStatusLabel(&result);
}

void SftpPanel::enterParentDirectory() {
  refreshRemoteListFor(parentRemotePath(currentRemoteDir()));
}

void SftpPanel::syncSelectedRemote(QListWidgetItem* item) {
  if (item == nullptr) {
    return;
  }
  selected_remote_edit_->setText(item->data(kPathRole).toString());
}

void SftpPanel::enterSelectedDirectory(QListWidgetItem* item) {
  if (item == nullptr) {
    return;
  }
  syncSelectedRemote(item);
  if (!item->data(kIsDirectoryRole).toBool()) {
    return;
  }
  refreshRemoteListFor(item->data(kPathRole).toString());
}

void SftpPanel::chooseUploadFile() {
  const auto file = QFileDialog::getOpenFileName(this, QStringLiteral("选择要上传的本地文件"));
  if (!file.isEmpty()) {
    upload_file_edit_->setText(file);
  }
}

void SftpPanel::chooseDownloadDirectory() {
  const auto directory = QFileDialog::getExistingDirectory(this, QStringLiteral("选择本地保存目录"));
  if (!directory.isEmpty()) {
    download_dir_edit_->setText(directory);
  }
}

void SftpPanel::uploadToCurrentDirectory() {
  auto local = upload_file_edit_->text().trimmed();
  if (local.isEmpty()) {
    chooseUploadFile();
    local = upload_file_edit_->text().trimmed();
  }
  if (local.isEmpty()) {
    return;
  }

  const QFileInfo local_info(local);
  const auto remote_target = joinRemotePath(currentRemoteDir(), local_info.fileName());
  const auto result = runBatch(
      {QStringLiteral("put %1 %2").arg(quoteSftpPath(local), quoteSftpPath(remote_target))},
      QStringLiteral("sftp_upload"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

void SftpPanel::downloadSelectedRemote() {
  const auto remote = selectedRemotePath();
  if (remote.isEmpty() || remote == QStringLiteral(".")) {
    QMessageBox::information(this, QStringLiteral("SFTP"), QStringLiteral("请先在左侧选择要下载的远端文件。"));
    return;
  }

  auto local_directory = download_dir_edit_->text().trimmed();
  if (local_directory.isEmpty()) {
    chooseDownloadDirectory();
    local_directory = download_dir_edit_->text().trimmed();
  }
  if (local_directory.isEmpty()) {
    return;
  }

  const bool selected_regular =
      remote_list_->currentItem() != nullptr &&
      remote_list_->currentItem()->data(kPathRole).toString() == remote &&
      remote_list_->currentItem()->data(kIsRegularFileRole).toBool();
  const auto command = selected_regular ? QStringLiteral("get %1 %2")
                                        : QStringLiteral("get -r %1 %2");
  const auto local_target = QDir(local_directory).filePath(fileNameFromRemotePath(remote));
  runBatch(
      {command.arg(quoteSftpPath(remote), quoteSftpPath(local_target))},
      QStringLiteral("sftp_download"),
      true);
}

void SftpPanel::renameSelectedRemote() {
  const auto old_path = selectedRemotePath();
  if (old_path.isEmpty() || old_path == QStringLiteral(".")) {
    QMessageBox::information(this, QStringLiteral("SFTP"), QStringLiteral("请先选择或填写远端对象。"));
    return;
  }

  bool ok = false;
  const auto new_name = QInputDialog::getText(
      this,
      QStringLiteral("重命名"),
      QStringLiteral("新名称或新路径"),
      QLineEdit::Normal,
      fileNameFromRemotePath(old_path),
      &ok);
  if (!ok || new_name.trimmed().isEmpty()) {
    return;
  }

  const auto new_path = new_name.trimmed().startsWith(QChar::fromLatin1('/'))
                            ? cleanRemotePath(new_name)
                            : joinRemotePath(currentRemoteDir(), new_name);
  const auto result = runBatch(
      {QStringLiteral("rename %1 %2").arg(quoteSftpPath(old_path), quoteSftpPath(new_path))},
      QStringLiteral("sftp_rename"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

void SftpPanel::createDirectory() {
  bool ok = false;
  const auto name = QInputDialog::getText(
      this,
      QStringLiteral("新建目录"),
      QStringLiteral("目录名"),
      QLineEdit::Normal,
      QString(),
      &ok);
  if (!ok || name.trimmed().isEmpty()) {
    return;
  }

  const auto remote_path = joinRemotePath(currentRemoteDir(), name);
  const auto result = runBatch(
      {QStringLiteral("mkdir %1").arg(quoteSftpPath(remote_path))},
      QStringLiteral("sftp_mkdir"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

void SftpPanel::deleteSelectedFile() {
  const auto remote = selectedRemotePath();
  if (remote.isEmpty() || remote == QStringLiteral(".")) {
    QMessageBox::information(this, QStringLiteral("SFTP"), QStringLiteral("请先选择或填写要删除的远端文件。"));
    return;
  }
  const auto confirm = QMessageBox::question(
      this,
      QStringLiteral("删除远端文件"),
      QStringLiteral("确认删除远端文件？\n%1").arg(remote));
  if (confirm != QMessageBox::Yes) {
    return;
  }

  const auto result = runBatch(
      {QStringLiteral("rm %1").arg(quoteSftpPath(remote))},
      QStringLiteral("sftp_delete"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

void SftpPanel::deleteSelectedDirectory() {
  const auto remote = selectedRemotePath();
  if (remote.isEmpty() || remote == QStringLiteral(".")) {
    QMessageBox::information(this, QStringLiteral("SFTP"), QStringLiteral("请先选择或填写要删除的远端空目录。"));
    return;
  }
  const auto confirm = QMessageBox::question(
      this,
      QStringLiteral("删除远端目录"),
      QStringLiteral("确认删除空目录？\n%1").arg(remote));
  if (confirm != QMessageBox::Yes) {
    return;
  }

  const auto result = runBatch(
      {QStringLiteral("rmdir %1").arg(quoteSftpPath(remote))},
      QStringLiteral("sftp_rmdir"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

void SftpPanel::chmodSelectedRemote() {
  const auto remote = selectedRemotePath();
  if (remote.isEmpty() || remote == QStringLiteral(".")) {
    QMessageBox::information(this, QStringLiteral("SFTP"), QStringLiteral("请先选择或填写远端对象。"));
    return;
  }

  bool ok = false;
  const auto mode = QInputDialog::getText(
      this,
      QStringLiteral("修改权限"),
      QStringLiteral("权限值（例如 600）"),
      QLineEdit::Normal,
      QStringLiteral("600"),
      &ok);
  const auto trimmed_mode = mode.trimmed();
  if (!ok || trimmed_mode.isEmpty()) {
    return;
  }
  if (!isOctalMode(trimmed_mode)) {
    QMessageBox::warning(this, QStringLiteral("修改权限"), QStringLiteral("权限值必须是 3-4 位八进制数。"));
    return;
  }

  const auto result = runBatch(
      {QStringLiteral("chmod %1 %2").arg(trimmed_mode, quoteSftpPath(remote))},
      QStringLiteral("sftp_chmod"),
      true);
  if (result.ok) {
    refreshRemoteList();
  }
}

SftpExecutionResult SftpPanel::runBatch(
    const QStringList& commands,
    const QString& event_name,
    bool show_success_output) {
  SftpExecutionResult result;
  if (!has_context_ || adapter_ == nullptr) {
    result.error = QStringLiteral("当前没有可用连接，请先建立 SSH 会话。");
    prependLogBlock(QStringLiteral("[错误] %1").arg(result.error));
    return result;
  }

  prependLogBlock(QStringLiteral("[执行] %1").arg(commands.join(QStringLiteral(" ; "))));
  setControlsEnabled(false);
  result = adapter_->runSftpBatch(profile_, secrets_, commands);
  setControlsEnabled(true);
  updateStatusLabel(&result);

  if (audit_logger_ != nullptr) {
    QJsonObject event{
        {QStringLiteral("profile"), profile_.name},
        {QStringLiteral("ok"), result.ok},
        {QStringLiteral("exit_code"), result.exit_code},
        {QStringLiteral("timed_out"), result.timed_out},
        {QStringLiteral("selected_mode"), toString(result.selected_mode)},
        {QStringLiteral("ssh_program"), result.ssh_program},
        {QStringLiteral("sftp_program"), result.sftp_program},
        {QStringLiteral("fallback_used"), result.fallback_used},
        {QStringLiteral("fallback_reason"), result.fallback_reason},
        {QStringLiteral("engine_fallback_used"), result.engine_fallback_used},
        {QStringLiteral("engine_fallback_reason"), result.engine_fallback_reason},
        {QStringLiteral("engine_fallback_from"), result.engine_fallback_from},
        {QStringLiteral("engine_fallback_to"), result.engine_fallback_to},
    };
    if (!result.error.trimmed().isEmpty()) {
      event.insert(QStringLiteral("error"), result.error.trimmed());
    }
    if (!result.std_err.trimmed().isEmpty()) {
      event.insert(QStringLiteral("stderr_tail"), stderrTailForAudit(result.std_err));
    }
    audit_logger_->logEvent(event_name, event);
  }

  if (result.engine_fallback_used) {
    prependLogBlock(
        QStringLiteral("[系统] 已自动切换 SFTP 引擎：%1").arg(
            engineFallbackReasonZh(result.engine_fallback_reason)));
  }
  if (result.fallback_used) {
    prependLogBlock(
        QStringLiteral("[系统] 算法回退：%1").arg(fallbackReasonZh(result.fallback_reason)));
  }

  if (!result.ok) {
    if (!result.sftp_program.trimmed().isEmpty()) {
      prependLogBlock(QStringLiteral("[诊断] SFTP 引擎：%1").arg(result.sftp_program));
    }
    if (!result.ssh_program.trimmed().isEmpty()) {
      prependLogBlock(QStringLiteral("[诊断] SSH 引擎：%1").arg(result.ssh_program));
    }
    if (!result.std_out.trimmed().isEmpty()) {
      prependLogBlock(result.std_out);
    }
    if (!result.std_err.trimmed().isEmpty()) {
      prependLogBlock(result.std_err);
    }
    if (!result.error.isEmpty()) {
      prependLogBlock(QStringLiteral("[错误] %1").arg(result.error));
    }
    const auto hint = failureHint(result);
    if (!hint.isEmpty()) {
      prependLogBlock(QStringLiteral("[提示] %1").arg(hint));
    }
    prependLogBlock(QStringLiteral("[错误] SFTP 退出码：%1").arg(result.exit_code));
    return result;
  }

  if (show_success_output) {
    if (!result.std_out.trimmed().isEmpty()) {
      prependLogBlock(result.std_out.trimmed());
    }
    if (!result.std_err.trimmed().isEmpty()) {
      prependLogBlock(result.std_err.trimmed());
    }
    prependLogBlock(QStringLiteral("[完成] 操作成功"));
  }
  return result;
}

void SftpPanel::prependLogBlock(QString text) {
  text = displaySafeDiagnostics(text);
  text = text.trimmed();
  if (text.isEmpty()) {
    return;
  }

  auto existing = output_view_->toPlainText().trimmed();
  auto combined = existing.isEmpty()
                      ? text
                      : QStringLiteral("%1\n\n%2").arg(text, existing);
  auto lines = combined.split(QChar::fromLatin1('\n'));
  if (lines.size() > kMaxLogLines) {
    lines = lines.mid(0, kMaxLogLines);
    combined = lines.join(QChar::fromLatin1('\n'));
  }

  output_view_->setPlainText(combined);
  QTextCursor cursor(output_view_->document());
  cursor.movePosition(QTextCursor::Start);
  output_view_->setTextCursor(cursor);
}

void SftpPanel::setControlsEnabled(bool enabled) {
  remote_dir_edit_->setEnabled(enabled);
  remote_list_->setEnabled(enabled);
  selected_remote_edit_->setEnabled(enabled);
  upload_file_edit_->setEnabled(enabled);
  download_dir_edit_->setEnabled(enabled);
  refresh_button_->setEnabled(enabled);
  parent_button_->setEnabled(enabled);
  choose_upload_button_->setEnabled(enabled);
  upload_button_->setEnabled(enabled);
  choose_download_dir_button_->setEnabled(enabled);
  download_button_->setEnabled(enabled);
  rename_button_->setEnabled(enabled);
  mkdir_button_->setEnabled(enabled);
  delete_file_button_->setEnabled(enabled);
  delete_dir_button_->setEnabled(enabled);
  chmod_button_->setEnabled(enabled);
}

void SftpPanel::updateStatusLabel(const SftpExecutionResult* result) {
  if (!has_context_) {
    status_label_->setText(QStringLiteral("未绑定 SSH 会话。请先连接主机。"));
    return;
  }

  QStringList parts;
  parts << QStringLiteral("会话：%1@%2:%3").arg(profile_.username, profile_.host).arg(profile_.port);
  parts << QStringLiteral("当前目录：%1").arg(currentRemoteDir());
  if (result != nullptr && !result->sftp_program.trimmed().isEmpty()) {
    parts << QStringLiteral("模式：%1").arg(algorithmModeZh(result->selected_mode));
    parts << QStringLiteral("SFTP：%1").arg(QFileInfo(result->sftp_program).fileName());
    if (result->engine_fallback_used) {
      parts << QStringLiteral("已引擎回退");
    }
  }
  status_label_->setText(parts.join(QStringLiteral("  |  ")));
}

}  // namespace gmssh
