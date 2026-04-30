#pragma once

#include "core/types.h"

#include <QDialog>

class QCheckBox;

namespace gmssh {

class ForwardingPanel;
class ProfileEditor;

class SessionProfileDialog : public QDialog {
  Q_OBJECT

 public:
  explicit SessionProfileDialog(QWidget* parent = nullptr);

  void setDialogTitle(const QString& title);
  void setProfile(const ConnectionProfile& profile);
  ConnectionProfile profile() const;

 private:
  ProfileEditor* profile_editor_ = nullptr;
  ForwardingPanel* forwarding_panel_ = nullptr;
  QCheckBox* advanced_check_ = nullptr;
};

}  // namespace gmssh
