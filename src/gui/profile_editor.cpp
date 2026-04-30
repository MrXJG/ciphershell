#include "gui/profile_editor.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QSizePolicy>
#include <QVBoxLayout>

namespace gmssh {
namespace {

constexpr int kDefaultFieldMaxWidth = 760;
constexpr int kPathFieldMaxWidth = 860;

void addComboItem(QComboBox* combo, const QString& label, const QString& value) {
  combo->addItem(label, value);
}

QString comboValue(const QComboBox* combo) {
  return combo->currentData().toString();
}

void setComboValue(QComboBox* combo, const QString& value) {
  const int index = combo->findData(value);
  if (index >= 0) {
    combo->setCurrentIndex(index);
  }
}

void configureFormLayout(QFormLayout* layout) {
  layout->setContentsMargins(8, 8, 8, 8);
  layout->setFormAlignment(Qt::AlignLeft | Qt::AlignTop);
  layout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
  layout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
  layout->setRowWrapPolicy(QFormLayout::WrapLongRows);
  layout->setHorizontalSpacing(16);
  layout->setVerticalSpacing(8);
}

void configureTextField(
    QLineEdit* edit,
    int minimum_width = 180,
    int maximum_width = kDefaultFieldMaxWidth) {
  edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  edit->setMinimumWidth(minimum_width);
  edit->setMaximumWidth(maximum_width);
}

void configureComboField(QComboBox* combo, int minimum_width = 180) {
  combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  combo->setMinimumWidth(minimum_width);
  combo->setMaximumWidth(kDefaultFieldMaxWidth);
}

int addRow(QFormLayout* layout, const QString& label, QWidget* field) {
  const int row = layout->rowCount();
  layout->addRow(label, field);
  return row;
}

void setFormRowVisible(QFormLayout* layout, int row, bool visible) {
  if (layout == nullptr || row < 0) {
    return;
  }

  if (auto* label_item = layout->itemAt(row, QFormLayout::LabelRole); label_item != nullptr) {
    if (auto* label_widget = label_item->widget(); label_widget != nullptr) {
      label_widget->setVisible(visible);
    }
  }
  if (auto* field_item = layout->itemAt(row, QFormLayout::FieldRole); field_item != nullptr) {
    if (auto* field_widget = field_item->widget(); field_widget != nullptr) {
      field_widget->setVisible(visible);
    }
  }
}

}  // namespace

ProfileEditor::ProfileEditor(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(8, 8, 8, 8);
  root->setSpacing(8);

  auto* profile_group = new QGroupBox(QStringLiteral("连接配置"), this);
  auto* form = new QFormLayout(profile_group);
  configureFormLayout(form);

  name_edit_ = new QLineEdit(profile_group);
  host_edit_ = new QLineEdit(profile_group);
  host_edit_->setPlaceholderText(QStringLiteral("例如：10.0.31.1"));
  port_edit_ = new QLineEdit(QStringLiteral("22"), profile_group);
  username_edit_ = new QLineEdit(profile_group);

  auth_method_combo_ = new QComboBox(profile_group);
  addComboItem(auth_method_combo_, QStringLiteral("密码"), QStringLiteral("password"));
  addComboItem(auth_method_combo_, QStringLiteral("SM2 密钥"), QStringLiteral("sm2_key"));
  addComboItem(auth_method_combo_, QStringLiteral("OpenSSH 证书"), QStringLiteral("openssh_cert"));
  addComboItem(auth_method_combo_, QStringLiteral("X.509/SM2 证书"), QStringLiteral("x509_sm2_cert"));

  key_path_edit_ = new QLineEdit(profile_group);
  cert_path_edit_ = new QLineEdit(profile_group);
  pfx_path_edit_ = new QLineEdit(profile_group);
  jump_host_edit_ = new QLineEdit(profile_group);

  algorithm_mode_combo_ = new QComboBox(profile_group);
  addComboItem(algorithm_mode_combo_, QStringLiteral("自动（优先国密）"), QStringLiteral("auto"));
  addComboItem(algorithm_mode_combo_, QStringLiteral("仅国密"), QStringLiteral("gm_only"));
  addComboItem(algorithm_mode_combo_, QStringLiteral("仅常规"), QStringLiteral("standard_only"));

  sftp_root_edit_ = new QLineEdit(profile_group);
  save_credential_check_ = new QCheckBox(QStringLiteral("保存凭据（加密存储）"), profile_group);

  audit_level_combo_ = new QComboBox(profile_group);
  addComboItem(audit_level_combo_, QStringLiteral("最小"), QStringLiteral("minimal"));
  addComboItem(audit_level_combo_, QStringLiteral("标准"), QStringLiteral("normal"));
  addComboItem(audit_level_combo_, QStringLiteral("详细"), QStringLiteral("verbose"));

  configureTextField(name_edit_);
  configureTextField(host_edit_);
  configureTextField(port_edit_, 100, 160);
  configureTextField(username_edit_);
  configureComboField(auth_method_combo_);
  configureTextField(key_path_edit_, 180, kPathFieldMaxWidth);
  configureTextField(cert_path_edit_, 180, kPathFieldMaxWidth);
  configureTextField(pfx_path_edit_, 180, kPathFieldMaxWidth);
  configureTextField(jump_host_edit_);
  configureComboField(algorithm_mode_combo_);
  configureTextField(sftp_root_edit_);
  configureComboField(audit_level_combo_);

  form->addRow(QStringLiteral("配置名称"), name_edit_);
  form->addRow(QStringLiteral("主机"), host_edit_);
  form->addRow(QStringLiteral("端口"), port_edit_);
  form->addRow(QStringLiteral("用户名"), username_edit_);
  form->addRow(QStringLiteral("认证方式"), auth_method_combo_);
  form->addRow(QStringLiteral(""), save_credential_check_);

  advanced_group_ = new QGroupBox(QStringLiteral("高级连接参数（可选）"), this);
  advanced_form_ = new QFormLayout(advanced_group_);
  configureFormLayout(advanced_form_);

  key_path_row_ = addRow(advanced_form_, QStringLiteral("私钥路径"), key_path_edit_);
  cert_path_row_ = addRow(advanced_form_, QStringLiteral("证书路径"), cert_path_edit_);
  pfx_path_row_ = addRow(advanced_form_, QStringLiteral("PFX 路径"), pfx_path_edit_);
  advanced_form_->addRow(QStringLiteral("跳板机"), jump_host_edit_);
  advanced_form_->addRow(QStringLiteral("算法策略"), algorithm_mode_combo_);
  advanced_form_->addRow(QStringLiteral("SFTP 默认路径"), sftp_root_edit_);
  advanced_form_->addRow(QStringLiteral("审计级别"), audit_level_combo_);

  secret_group_ = new QGroupBox(QStringLiteral("会话密钥（不写入配置文件）"), this);
  secret_form_ = new QFormLayout(secret_group_);
  configureFormLayout(secret_form_);
  password_edit_ = new QLineEdit(secret_group_);
  password_edit_->setEchoMode(QLineEdit::Password);

  pfx_password_edit_ = new QLineEdit(secret_group_);
  pfx_password_edit_->setEchoMode(QLineEdit::Password);
  configureTextField(password_edit_, 200);
  configureTextField(pfx_password_edit_, 200);

  password_row_ = addRow(secret_form_, QStringLiteral("登录密码"), password_edit_);
  pfx_password_row_ = addRow(secret_form_, QStringLiteral("PFX 密码"), pfx_password_edit_);

  root->addWidget(profile_group);
  root->addWidget(advanced_group_);
  root->addWidget(secret_group_);
  root->addStretch(1);

  connect(
      auth_method_combo_,
      &QComboBox::currentIndexChanged,
      this,
      [this](int) { updateAuthUi(); });
  connect(
      pfx_path_edit_,
      &QLineEdit::textChanged,
      this,
      [this](const QString&) { updateAuthUi(); });

  setAdvancedVisible(false);
  updateAuthUi();
}

void ProfileEditor::setProfile(const ConnectionProfile& profile) {
  name_edit_->setText(profile.name);
  host_edit_->setText(profile.host);
  port_edit_->setText(QString::number(profile.port));
  username_edit_->setText(profile.username);
  setComboValue(auth_method_combo_, toString(profile.auth_method));
  key_path_edit_->setText(profile.key_path);
  cert_path_edit_->setText(profile.cert_path);
  pfx_path_edit_->setText(profile.pfx_path);
  jump_host_edit_->setText(profile.jump_host);
  setComboValue(algorithm_mode_combo_, toString(profile.algorithm_mode));
  sftp_root_edit_->setText(profile.sftp_root);
  save_credential_check_->setChecked(profile.save_credential);
  setComboValue(audit_level_combo_, toString(profile.audit_level));
  updateAuthUi();
}

ConnectionProfile ProfileEditor::profile() const {
  ConnectionProfile profile;
  profile.name = name_edit_->text().trimmed();
  profile.host = host_edit_->text().trimmed();
  bool ok = false;
  const int parsed_port = port_edit_->text().toInt(&ok);
  profile.port = ok ? parsed_port : 22;
  profile.username = username_edit_->text().trimmed();
  profile.auth_method =
      authMethodFromString(comboValue(auth_method_combo_)).value_or(AuthMethod::Password);
  profile.key_path = key_path_edit_->text().trimmed();
  profile.cert_path = cert_path_edit_->text().trimmed();
  profile.pfx_path = pfx_path_edit_->text().trimmed();
  profile.jump_host = jump_host_edit_->text().trimmed();
  profile.algorithm_mode =
      algorithmModeFromString(comboValue(algorithm_mode_combo_)).value_or(AlgorithmMode::Auto);
  profile.sftp_root = sftp_root_edit_->text().trimmed();
  profile.save_credential = save_credential_check_->isChecked();
  profile.audit_level =
      auditLevelFromString(comboValue(audit_level_combo_)).value_or(AuditLevel::Normal);
  return profile;
}

SessionSecrets ProfileEditor::sessionSecrets() const {
  SessionSecrets secrets;
  secrets.password = password_edit_->text();
  secrets.pfx_password = pfx_password_edit_->text();
  return secrets;
}

void ProfileEditor::clearForNewProfile() {
  name_edit_->clear();
  host_edit_->clear();
  port_edit_->setText(QStringLiteral("22"));
  username_edit_->clear();
  setComboValue(auth_method_combo_, QStringLiteral("password"));
  key_path_edit_->clear();
  cert_path_edit_->clear();
  pfx_path_edit_->clear();
  jump_host_edit_->clear();
  setComboValue(algorithm_mode_combo_, QStringLiteral("auto"));
  sftp_root_edit_->clear();
  save_credential_check_->setChecked(false);
  setComboValue(audit_level_combo_, QStringLiteral("normal"));
  password_edit_->clear();
  pfx_password_edit_->clear();
  setAdvancedVisible(false);
  updateAuthUi();
}

void ProfileEditor::setAdvancedVisible(bool visible) {
  if (advanced_group_ != nullptr) {
    advanced_group_->setVisible(visible);
  }
  emit advancedVisibilityChanged(visible);
}

bool ProfileEditor::advancedVisible() const {
  return advanced_group_ != nullptr && advanced_group_->isVisible();
}

void ProfileEditor::setSecretVisible(bool visible) {
  if (secret_group_ != nullptr) {
    secret_group_->setVisible(visible);
  }
}

bool ProfileEditor::secretVisible() const {
  return secret_group_ != nullptr && secret_group_->isVisible();
}

void ProfileEditor::updateAuthUi() {
  const auto method =
      authMethodFromString(comboValue(auth_method_combo_)).value_or(AuthMethod::Password);
  const bool has_pfx = !pfx_path_edit_->text().trimmed().isEmpty();

  const bool need_key = method == AuthMethod::Sm2Key || method == AuthMethod::OpenSshCert;
  const bool need_cert = method == AuthMethod::OpenSshCert;
  const bool need_pfx = method == AuthMethod::X509Sm2Cert;
  const bool show_password = method == AuthMethod::Password;
  const bool show_pfx_password = method == AuthMethod::X509Sm2Cert && has_pfx;

  setFormRowVisible(advanced_form_, key_path_row_, need_key);
  setFormRowVisible(advanced_form_, cert_path_row_, need_cert);
  setFormRowVisible(advanced_form_, pfx_path_row_, need_pfx);
  setFormRowVisible(secret_form_, password_row_, show_password);
  setFormRowVisible(secret_form_, pfx_password_row_, show_pfx_password);

  if (!show_password) {
    password_edit_->clear();
  }
  if (!show_pfx_password) {
    pfx_password_edit_->clear();
  }

  const bool requires_advanced_input = need_key || need_cert || need_pfx;
  if (requires_advanced_input && !advancedVisible()) {
    setAdvancedVisible(true);
  }
}

}  // namespace gmssh
