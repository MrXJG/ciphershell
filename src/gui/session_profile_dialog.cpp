#include "gui/session_profile_dialog.h"

#include "gui/forwarding_panel.h"
#include "gui/profile_editor.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>

namespace gmssh {

SessionProfileDialog::SessionProfileDialog(QWidget* parent) : QDialog(parent) {
  setObjectName(QStringLiteral("sessionProfileDialog"));
  setModal(true);
  setMinimumSize(740, 560);
  resize(820, 640);
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(12, 10, 12, 10);
  root->setSpacing(8);

  auto* top_row = new QHBoxLayout();
  auto* hint_label = new QLabel(QStringLiteral("配置会话参数后保存，再从主界面发起连接。"), this);
  top_row->addWidget(hint_label);
  top_row->addStretch();

  advanced_check_ = new QCheckBox(QStringLiteral("显示高级连接参数"), this);
  advanced_check_->setChecked(false);
  top_row->addWidget(advanced_check_);
  root->addLayout(top_row);

  auto* tabs = new QTabWidget(this);
  tabs->setObjectName(QStringLiteral("sessionProfileTabs"));
  tabs->setDocumentMode(false);
  tabs->setUsesScrollButtons(false);
  tabs->tabBar()->setObjectName(QStringLiteral("sessionProfileTabBar"));
  tabs->tabBar()->setExpanding(false);
  tabs->tabBar()->setElideMode(Qt::ElideRight);
  profile_editor_ = new ProfileEditor(tabs);
  profile_editor_->setSecretVisible(false);
  profile_editor_->setAdvancedVisible(false);

  forwarding_panel_ = new ForwardingPanel(tabs);

  tabs->addTab(profile_editor_, QStringLiteral("连接参数"));
  tabs->addTab(forwarding_panel_, QStringLiteral("端口转发"));
  root->addWidget(tabs, 1);

  auto* button_box =
      new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
  button_box->button(QDialogButtonBox::Save)->setText(QStringLiteral("保存"));
  button_box->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  root->addWidget(button_box);

  connect(button_box, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(button_box, &QDialogButtonBox::rejected, this, &QDialog::reject);
  connect(advanced_check_, &QCheckBox::toggled, profile_editor_, &ProfileEditor::setAdvancedVisible);
  connect(
      profile_editor_,
      &ProfileEditor::advancedVisibilityChanged,
      this,
      [this](bool visible) {
        if (advanced_check_ == nullptr || advanced_check_->isChecked() == visible) {
          return;
        }
        const QSignalBlocker blocker(advanced_check_);
        advanced_check_->setChecked(visible);
      });
}

void SessionProfileDialog::setDialogTitle(const QString& title) {
  setWindowTitle(title);
}

void SessionProfileDialog::setProfile(const ConnectionProfile& profile) {
  profile_editor_->setProfile(profile);
  forwarding_panel_->setRules(profile.forwarding_rules);
  const QSignalBlocker blocker(advanced_check_);
  advanced_check_->setChecked(profile_editor_->advancedVisible());
}

ConnectionProfile SessionProfileDialog::profile() const {
  auto result = profile_editor_->profile();
  result.forwarding_rules = forwarding_panel_->rules();
  return result;
}

}  // namespace gmssh
