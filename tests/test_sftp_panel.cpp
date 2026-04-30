#include "gui/audit_log_view.h"
#include "gui/main_window.h"
#include "gui/profile_editor.h"
#include "gui/session_profile_dialog.h"
#include "gui/sftp_panel.h"
#include "gui/terminal_session_widget.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QFile>
#include <QFrame>
#include <QGroupBox>
#include <QHeaderView>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QResource>
#include <QStandardPaths>
#include <QTabBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTimer>
#include <QWidget>

#include <cassert>

using namespace gmssh;

QString localTerminalTestProgram() {
#if defined(Q_OS_WIN)
  return QStringLiteral("cmd.exe");
#else
  return QStringLiteral("/bin/sh");
#endif
}

QStringList localTerminalTestArguments(const QString& command) {
#if defined(Q_OS_WIN)
  return {QStringLiteral("/c"), command};
#else
  return {QStringLiteral("-lc"), command};
#endif
}

void test_profile_editor_save_credential_location() {
  ProfileEditor editor;

  QCheckBox* save_check = nullptr;
  for (auto* check : editor.findChildren<QCheckBox*>()) {
    if (check->text().contains(QStringLiteral("保存凭据"))) {
      save_check = check;
      break;
    }
  }

  assert(save_check != nullptr);
  auto* parent_group = qobject_cast<QGroupBox*>(save_check->parentWidget());
  assert(parent_group != nullptr);
  assert(parent_group->title() == QStringLiteral("连接配置"));

  for (auto* edit : editor.findChildren<QLineEdit*>()) {
    assert(edit->maximumWidth() <= 860);
  }
}

void test_visual_font_stack_prefers_platform_native_fonts() {
  MainWindow window;
  const auto style_sheet = qApp->styleSheet();
  assert(style_sheet.contains(QStringLiteral("Segoe UI")));
  assert(style_sheet.contains(QStringLiteral("Microsoft YaHei UI")));
  assert(style_sheet.contains(QStringLiteral("Cascadia Mono")));
  assert(style_sheet.contains(QStringLiteral("Consolas")));
  assert(!style_sheet.contains(QStringLiteral("Matter")));
  assert(!style_sheet.contains(QStringLiteral("Geist Mono")));
}

void test_combo_arrow_resource_is_available() {
  QResource arrow(QStringLiteral(":/icons/icons/chevron-down.png"));
  assert(arrow.isValid());
  assert(arrow.size() > 0);
}

void test_checkbox_checkmark_resource_is_png() {
  MainWindow window;
  const auto style_sheet = qApp->styleSheet();
  assert(style_sheet.contains(QStringLiteral("check-light.png")));
  assert(!style_sheet.contains(QStringLiteral("check-light.svg")));

  QResource checkmark(QStringLiteral(":/icons/icons/check-light.png"));
  assert(checkmark.isValid());
  assert(checkmark.size() > 0);
}

void test_audit_log_view_shows_log_file_path() {
  QTemporaryDir temp_dir;
  assert(temp_dir.isValid());
  const auto log_path = temp_dir.filePath(QStringLiteral("log/audit.log"));

  AuditLogView view;
  view.setLogFilePath(log_path);
  view.refresh();

  auto* path_label = view.findChild<QLabel*>(QStringLiteral("auditLogPathLabel"));
  assert(path_label != nullptr);
  assert(path_label->text().contains(log_path));

  auto* text = view.findChild<QPlainTextEdit*>();
  assert(text != nullptr);
  assert(text->toPlainText().contains(log_path));
}

void test_session_profile_dialog_uses_compact_tabs() {
  SessionProfileDialog dialog;

  auto* tabs = dialog.findChild<QTabWidget*>(QStringLiteral("sessionProfileTabs"));
  assert(tabs != nullptr);
  assert(tabs->tabBar() != nullptr);
  assert(tabs->tabBar()->objectName() == QStringLiteral("sessionProfileTabBar"));
  assert(!tabs->tabBar()->expanding());
  assert(tabs->count() == 2);

  auto* forwarding_frame = dialog.findChild<QFrame*>(QStringLiteral("forwardingTableFrame"));
  assert(forwarding_frame != nullptr);
  auto* forwarding_table = dialog.findChild<QTableWidget*>(QStringLiteral("forwardingRulesTable"));
  assert(forwarding_table != nullptr);
  assert(forwarding_table->frameShape() == QFrame::NoFrame);
  assert(!forwarding_table->showGrid());
  assert(!forwarding_table->verticalHeader()->isVisible());

  QPushButton* add_rule_button = nullptr;
  for (auto* button : dialog.findChildren<QPushButton*>()) {
    if (button->text() == QStringLiteral("新增规则")) {
      add_rule_button = button;
      break;
    }
  }
  assert(add_rule_button != nullptr);
  add_rule_button->click();

  auto* forwarding_combo =
      forwarding_table->findChild<QComboBox*>(QStringLiteral("forwardingRuleTypeCombo"));
  assert(forwarding_combo != nullptr);
  assert(forwarding_combo->cursor().shape() == Qt::PointingHandCursor);

  const auto forwarding_edits =
      forwarding_table->findChildren<QLineEdit*>(QStringLiteral("forwardingRuleCellEdit"));
  assert(forwarding_edits.size() == 2);
  assert(!forwarding_edits.at(0)->placeholderText().isEmpty());
  assert(!forwarding_edits.at(1)->placeholderText().isEmpty());
  assert(forwarding_edits.at(0)->hasFrame());
  assert(forwarding_edits.at(1)->hasFrame());

  forwarding_edits.at(0)->setText(QStringLiteral("127.0.0.1:8080"));
  forwarding_edits.at(1)->setText(QStringLiteral("10.0.13.1:22"));
  const auto profile = dialog.profile();
  assert(profile.forwarding_rules.size() == 1);
  assert(profile.forwarding_rules.first().bind_port_or_path == QStringLiteral("127.0.0.1:8080"));
  assert(profile.forwarding_rules.first().target_addr == QStringLiteral("10.0.13.1"));
  assert(profile.forwarding_rules.first().target_port_or_path == QStringLiteral("22"));
}

void test_sftp_path_enter_is_not_forwarded_to_dialog_buttons() {
  SftpPanel panel;

  QLineEdit* remote_dir_edit = nullptr;
  for (auto* edit : panel.findChildren<QLineEdit*>()) {
    if (edit->placeholderText().contains(QStringLiteral("回车刷新"))) {
      remote_dir_edit = edit;
      break;
    }
  }
  assert(remote_dir_edit != nullptr);

  for (auto* button : panel.findChildren<QPushButton*>()) {
    assert(!button->autoDefault());
    assert(!button->isDefault());
  }

  auto* output = panel.findChild<QPlainTextEdit*>();
  assert(output != nullptr);
  output->setPlainText(QStringLiteral("OLD LOG"));
  remote_dir_edit->setText(QStringLiteral("/root"));
  QKeyEvent enter_event(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
  QApplication::sendEvent(remote_dir_edit, &enter_event);

  const auto output_text = output->toPlainText();
  assert(output_text.startsWith(QStringLiteral("[错误] 当前没有可用连接")));
  assert(output_text.contains(QStringLiteral("\n\nOLD LOG")));
  assert(output_text.contains(QStringLiteral("当前没有可用连接")));
  assert(output_text.count(QStringLiteral("当前没有可用连接")) == 1);
}

void test_terminal_status_follows_active_tab() {
  MainWindow window;

  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("terminalTabs"));
  assert(tabs != nullptr);
  assert(!tabs->tabsClosable());
  auto* status = window.findChild<QLabel*>(QStringLiteral("statusPill"));
  assert(status != nullptr);

  auto* openeuler_tab = new QWidget(tabs);
  openeuler_tab->setProperty(
      "gmssh_status_text",
      QStringLiteral("已连接：root@10.0.13.2:2222  ｜  连接方式：国密 SSH 直连"));
  auto* kylin_tab = new QWidget(tabs);
  kylin_tab->setProperty(
      "gmssh_status_text",
      QStringLiteral("已连接：root@10.0.13.1:22  ｜  连接方式：国密 SSH 直连"));

  tabs->addTab(openeuler_tab, QStringLiteral("openEuler"));
  tabs->addTab(kylin_tab, QStringLiteral("麒麟 V10 SP3"));

  tabs->setCurrentIndex(0);
  QCoreApplication::processEvents();
  assert(status->text().contains(QStringLiteral("10.0.13.2:2222")));

  tabs->setCurrentIndex(1);
  QCoreApplication::processEvents();
  assert(status->text().contains(QStringLiteral("10.0.13.1:22")));
  assert(!status->text().contains(QStringLiteral("10.0.13.2:2222")));
}

void test_session_center_stays_compact() {
  MainWindow window;

  auto* left_panel = window.findChild<QWidget*>(QStringLiteral("leftPanel"));
  assert(left_panel != nullptr);
  assert(left_panel->minimumWidth() == 200);
  assert(left_panel->maximumWidth() == 240);
}

void test_terminal_uses_inline_terminal_surface() {
  ConnectionProfile profile;
  profile.name = QStringLiteral("测试终端");
  profile.host = QStringLiteral("127.0.0.1");
  profile.username = QStringLiteral("root");

  SessionSecrets secrets;
  SshLaunchPlan launch_plan;
  launch_plan.ok = false;
  launch_plan.error = QStringLiteral("test-only");

  TerminalSessionWidget terminal(
      QStringLiteral("测试终端"),
      profile,
      secrets,
      launch_plan,
      nullptr);

  assert(terminal.findChild<QLineEdit*>(QStringLiteral("terminalCommandInput")) == nullptr);
  auto* output = terminal.findChild<QPlainTextEdit*>(QStringLiteral("terminalOutputView"));
  assert(output != nullptr);
  assert(output->focusPolicy() == Qt::StrongFocus);
  assert(output->isReadOnly());
  assert(terminal.findChildren<QPushButton*>().isEmpty());
}

void test_terminal_backend_runs_local_command_and_audits_output() {
  QTemporaryDir temp_dir;
  assert(temp_dir.isValid());
  AuditLogger audit_logger(temp_dir.filePath(QStringLiteral("audit.jsonl")));

  ConnectionProfile profile;
  profile.name = QStringLiteral("本地终端测试");
  profile.host = QStringLiteral("127.0.0.1");
  profile.username = QStringLiteral("tester");
  profile.audit_level = AuditLevel::Normal;

  SshLaunchPlan launch_plan;
  launch_plan.ok = true;
  launch_plan.program = localTerminalTestProgram();
  launch_plan.arguments = localTerminalTestArguments(QStringLiteral("echo TERMINAL_WIDGET_OK"));
  launch_plan.environment = QProcessEnvironment::systemEnvironment();
  launch_plan.selected_mode = AlgorithmMode::StandardOnly;

  TerminalSessionWidget terminal(
      QStringLiteral("本地终端测试"),
      profile,
      SessionSecrets{},
      launch_plan,
      &audit_logger);

  bool closed = false;
  QEventLoop loop;
  QObject::connect(&terminal, &TerminalSessionWidget::sessionClosed, &loop, [&]() {
    closed = true;
    loop.quit();
  });
  QTimer::singleShot(4000, &loop, &QEventLoop::quit);
  loop.exec();

  assert(closed);
  auto* output = terminal.findChild<QPlainTextEdit*>(QStringLiteral("terminalOutputView"));
  assert(output != nullptr);
  assert(output->toPlainText().contains(QStringLiteral("TERMINAL_WIDGET_OK")));

  QFile audit_file(audit_logger.logFilePath());
  assert(audit_file.open(QIODevice::ReadOnly | QIODevice::Text));
  const auto audit_text = QString::fromUtf8(audit_file.readAll());
  assert(audit_text.contains(QStringLiteral("terminal_output")));
  assert(audit_text.contains(QStringLiteral("TERMINAL_WIDGET_OK")));
  assert(audit_text.contains(QStringLiteral("session_closed")));
}

void test_terminal_crlf_layout_uses_separate_lines() {
  ConnectionProfile profile;
  profile.name = QStringLiteral("本地排版测试");
  profile.host = QStringLiteral("127.0.0.1");
  profile.username = QStringLiteral("tester");
  profile.audit_level = AuditLevel::Minimal;

  SshLaunchPlan launch_plan;
  launch_plan.ok = true;
  launch_plan.program = localTerminalTestProgram();
  launch_plan.arguments = localTerminalTestArguments(
      QStringLiteral("echo PROMPT# ls&&echo file-a file-b&&echo PROMPT#"));
  launch_plan.environment = QProcessEnvironment::systemEnvironment();
  launch_plan.selected_mode = AlgorithmMode::StandardOnly;

  TerminalSessionWidget terminal(
      QStringLiteral("本地排版测试"),
      profile,
      SessionSecrets{},
      launch_plan,
      nullptr);

  bool closed = false;
  QEventLoop loop;
  QObject::connect(&terminal, &TerminalSessionWidget::sessionClosed, &loop, [&]() {
    closed = true;
    loop.quit();
  });
  QTimer::singleShot(4000, &loop, &QEventLoop::quit);
  loop.exec();

  assert(closed);
  auto* output = terminal.findChild<QPlainTextEdit*>(QStringLiteral("terminalOutputView"));
  assert(output != nullptr);
  const auto text = output->toPlainText();
  assert(text.contains(QStringLiteral("PROMPT# ls\nfile-a file-b\nPROMPT#")));
  assert(!text.contains(QStringLiteral("PROMPT# lsfile-a")));
}

void test_sftp_context_can_be_cleared() {
  SftpPanel panel;

  ConnectionProfile profile;
  profile.name = QStringLiteral("openEuler");
  profile.host = QStringLiteral("10.0.13.2");
  profile.port = 2222;
  profile.username = QStringLiteral("root");

  panel.setContext(profile, SessionSecrets{});
  auto* status = panel.findChild<QLabel*>();
  assert(status != nullptr);
  assert(status->text().contains(QStringLiteral("10.0.13.2")));

  panel.clearContext();
  assert(status->text().contains(QStringLiteral("未绑定 SSH 会话")));
}

int main(int argc, char** argv) {
  qputenv("QT_QPA_PLATFORM", "offscreen");
  QStandardPaths::setTestModeEnabled(true);

  QApplication app(argc, argv);
  test_profile_editor_save_credential_location();
  test_visual_font_stack_prefers_platform_native_fonts();
  test_combo_arrow_resource_is_available();
  test_checkbox_checkmark_resource_is_png();
  test_audit_log_view_shows_log_file_path();
  test_session_profile_dialog_uses_compact_tabs();
  test_sftp_path_enter_is_not_forwarded_to_dialog_buttons();
  test_terminal_status_follows_active_tab();
  test_session_center_stays_compact();
  test_terminal_uses_inline_terminal_surface();
  test_terminal_backend_runs_local_command_and_audits_output();
  test_terminal_crlf_layout_uses_separate_lines();
  test_sftp_context_can_be_cleared();
  return 0;
}
