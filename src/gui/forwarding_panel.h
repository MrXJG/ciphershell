#pragma once

#include "core/types.h"

#include <QPushButton>
#include <QTableWidget>
#include <QWidget>

namespace gmssh {

class ForwardingPanel : public QWidget {
  Q_OBJECT

 public:
  explicit ForwardingPanel(QWidget* parent = nullptr);

  void setRules(const QList<ForwardRule>& rules);
  QList<ForwardRule> rules() const;

 private:
  void addRuleRow(const ForwardRule& rule);

  QTableWidget* table_;
  QPushButton* add_button_;
  QPushButton* remove_button_;
};

}  // namespace gmssh
