#include "gui/forwarding_panel.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QVBoxLayout>

namespace gmssh {
namespace {

void addTypeItems(QComboBox* combo) {
  combo->addItem(QStringLiteral("本地转发"), QStringLiteral("local"));
  combo->addItem(QStringLiteral("远程转发"), QStringLiteral("remote"));
  combo->addItem(QStringLiteral("动态代理 (SOCKS)"), QStringLiteral("dynamic_socks"));
  combo->addItem(QStringLiteral("UnixSocket 转发"), QStringLiteral("unix_socket"));
}

void setTypeValue(QComboBox* combo, ForwardType type) {
  const int idx = combo->findData(toString(type));
  if (idx >= 0) {
    combo->setCurrentIndex(idx);
  }
}

QString currentTypeValue(const QComboBox* combo) {
  return combo->currentData().toString();
}

QString lineEditValue(const QTableWidget* table, int row, int column) {
  auto* edit = qobject_cast<QLineEdit*>(table->cellWidget(row, column));
  if (edit != nullptr) {
    return edit->text().trimmed();
  }

  const auto* item = table->item(row, column);
  return item != nullptr ? item->text().trimmed() : QString();
}

void configureCellEdit(QLineEdit* edit, const QString& placeholder) {
  edit->setObjectName(QStringLiteral("forwardingRuleCellEdit"));
  edit->setPlaceholderText(placeholder);
  edit->setFrame(true);
  edit->setClearButtonEnabled(true);
}

void updateRowInputHints(QComboBox* combo, QLineEdit* bind_edit, QLineEdit* target_edit) {
  const auto type =
      forwardTypeFromString(combo->currentData().toString()).value_or(ForwardType::Local);

  switch (type) {
    case ForwardType::Local:
      bind_edit->setPlaceholderText(QStringLiteral("例如 127.0.0.1:8080 或 8080"));
      target_edit->setPlaceholderText(QStringLiteral("例如 10.0.13.1:22"));
      target_edit->setEnabled(true);
      break;
    case ForwardType::Remote:
      bind_edit->setPlaceholderText(QStringLiteral("例如 0.0.0.0:9090 或 9090"));
      target_edit->setPlaceholderText(QStringLiteral("例如 127.0.0.1:22"));
      target_edit->setEnabled(true);
      break;
    case ForwardType::DynamicSocks:
      bind_edit->setPlaceholderText(QStringLiteral("例如 127.0.0.1:1080 或 1080"));
      target_edit->clear();
      target_edit->setPlaceholderText(QStringLiteral("动态代理无需目标地址"));
      target_edit->setEnabled(false);
      break;
    case ForwardType::UnixSocket:
      bind_edit->setPlaceholderText(QStringLiteral("例如 /tmp/local.sock"));
      target_edit->setPlaceholderText(QStringLiteral("例如 /tmp/remote.sock"));
      target_edit->setEnabled(true);
      break;
  }
}

}  // namespace

ForwardingPanel::ForwardingPanel(QWidget* parent) : QWidget(parent) {
  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(8, 8, 8, 8);
  layout->setSpacing(8);

  auto* table_frame = new QFrame(this);
  table_frame->setObjectName(QStringLiteral("forwardingTableFrame"));
  auto* table_frame_layout = new QVBoxLayout(table_frame);
  table_frame_layout->setContentsMargins(8, 8, 8, 8);
  table_frame_layout->setSpacing(0);

  table_ = new QTableWidget(table_frame);
  table_->setObjectName(QStringLiteral("forwardingRulesTable"));
  table_->setFrameShape(QFrame::NoFrame);
  table_->setColumnCount(3);
  table_->setAlternatingRowColors(true);
  table_->setShowGrid(false);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setCornerButtonEnabled(false);
  table_->verticalHeader()->setVisible(false);
  table_->setHorizontalHeaderLabels(
      {QStringLiteral("类型"),
       QStringLiteral("监听地址/端口(或路径)"),
       QStringLiteral("目标地址:端口(或路径)")});
  table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  table_->horizontalHeader()->setHighlightSections(false);
  table_->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
  table_frame_layout->addWidget(table_);

  add_button_ = new QPushButton(QStringLiteral("新增规则"), this);
  remove_button_ = new QPushButton(QStringLiteral("删除规则"), this);
  add_button_->setMinimumWidth(0);
  remove_button_->setMinimumWidth(0);

  auto* button_row = new QHBoxLayout();
  button_row->setContentsMargins(0, 0, 0, 0);
  button_row->setSpacing(8);
  button_row->addWidget(add_button_);
  button_row->addWidget(remove_button_);
  button_row->addStretch();

  layout->addWidget(table_frame, 1);
  layout->addLayout(button_row);

  connect(add_button_, &QPushButton::clicked, this, [this]() {
    addRuleRow(ForwardRule{});
  });

  connect(remove_button_, &QPushButton::clicked, this, [this]() {
    const auto row = table_->currentRow();
    if (row >= 0) {
      table_->removeRow(row);
    }
  });
}

void ForwardingPanel::setRules(const QList<ForwardRule>& rules) {
  table_->setRowCount(0);
  for (const auto& rule : rules) {
    addRuleRow(rule);
  }
}

QList<ForwardRule> ForwardingPanel::rules() const {
  QList<ForwardRule> rules;

  for (int row = 0; row < table_->rowCount(); ++row) {
    ForwardRule rule;

    auto* combo = qobject_cast<QComboBox*>(table_->cellWidget(row, 0));
    const auto type_value = combo != nullptr ? currentTypeValue(combo) : QStringLiteral("local");
    rule.type = forwardTypeFromString(type_value).value_or(ForwardType::Local);

    rule.bind_port_or_path = lineEditValue(table_, row, 1);

    const auto target = lineEditValue(table_, row, 2);
    const auto parts = target.split(':');
    if (parts.size() >= 2) {
      rule.target_addr = parts[0];
      rule.target_port_or_path = parts.mid(1).join(QLatin1Char(':'));
    } else {
      rule.target_addr = target;
    }

    if (!rule.bind_port_or_path.isEmpty()) {
      rules.push_back(rule);
    }
  }

  return rules;
}

void ForwardingPanel::addRuleRow(const ForwardRule& rule) {
  const int row = table_->rowCount();
  table_->insertRow(row);

  auto* combo = new QComboBox(table_);
  combo->setObjectName(QStringLiteral("forwardingRuleTypeCombo"));
  combo->setCursor(Qt::PointingHandCursor);
  addTypeItems(combo);
  setTypeValue(combo, rule.type);
  table_->setCellWidget(row, 0, combo);

  auto* bind_edit = new QLineEdit(table_);
  configureCellEdit(bind_edit, QStringLiteral("监听地址/端口或路径"));
  bind_edit->setText(rule.bind_port_or_path);
  table_->setCellWidget(row, 1, bind_edit);

  const auto target = rule.target_port_or_path.isEmpty()
                          ? rule.target_addr
                          : QStringLiteral("%1:%2").arg(rule.target_addr, rule.target_port_or_path);
  auto* target_edit = new QLineEdit(table_);
  configureCellEdit(target_edit, QStringLiteral("目标地址:端口或路径"));
  target_edit->setText(target);
  table_->setCellWidget(row, 2, target_edit);

  updateRowInputHints(combo, bind_edit, target_edit);
  QObject::connect(combo, &QComboBox::currentIndexChanged, table_, [combo, bind_edit, target_edit]() {
    updateRowInputHints(combo, bind_edit, target_edit);
  });
}

}  // namespace gmssh
