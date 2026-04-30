#pragma once

#include "core/types.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QWidget>

namespace gmssh {

class ProfileEditor : public QWidget {
  Q_OBJECT

 public:
  explicit ProfileEditor(QWidget* parent = nullptr);

  void setProfile(const ConnectionProfile& profile);
  ConnectionProfile profile() const;
  SessionSecrets sessionSecrets() const;

  void clearForNewProfile();
  void setAdvancedVisible(bool visible);
  bool advancedVisible() const;
  void setSecretVisible(bool visible);
  bool secretVisible() const;

 signals:
  void advancedVisibilityChanged(bool visible);

 private:
  void updateAuthUi();

  QGroupBox* advanced_group_ = nullptr;
  QGroupBox* secret_group_ = nullptr;
  QFormLayout* advanced_form_ = nullptr;
  QFormLayout* secret_form_ = nullptr;

  QLineEdit* name_edit_;
  QLineEdit* host_edit_;
  QLineEdit* port_edit_;
  QLineEdit* username_edit_;
  QComboBox* auth_method_combo_;
  QLineEdit* key_path_edit_;
  QLineEdit* cert_path_edit_;
  QLineEdit* pfx_path_edit_;
  QLineEdit* jump_host_edit_;
  QComboBox* algorithm_mode_combo_;
  QLineEdit* sftp_root_edit_;
  QCheckBox* save_credential_check_;
  QComboBox* audit_level_combo_;

  QLineEdit* password_edit_;
  QLineEdit* pfx_password_edit_;

  int key_path_row_ = -1;
  int cert_path_row_ = -1;
  int pfx_path_row_ = -1;
  int password_row_ = -1;
  int pfx_password_row_ = -1;
};

}  // namespace gmssh
