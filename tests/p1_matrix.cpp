#include "core/credential_store.h"
#include "core/profile_repository.h"
#include "core/ssh_engine_adapter.h"
#include "core/types.h"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QThread>

#include <iostream>
#include <optional>

using namespace gmssh;

namespace {

constexpr int kProcessTimeoutMs = 35000;
constexpr int kForwardTimeoutMs = 12000;

struct RuntimeConfig {
  QString profiles_path;
  QString credentials_path;
  QString known_hosts_path;
  QString modern_ssh;
  QString modern_sftp;
  QString legacy_ssh;
  QString legacy_sftp;
  QString output_json_path;
};

struct MatrixCase {
  QString name;
  QString source_profile;
  int port = 0;
  AlgorithmMode mode = AlgorithmMode::Auto;
  GmHostSignaturePolicy policy = GmHostSignaturePolicy::Strict;
  bool expect_terminal_ok = false;
  bool expect_sftp_ok = false;
  bool expect_forward_ok = false;
};

struct OperationResult {
  bool ok = false;
  QString detail;
  QString selected_mode;
  bool algorithm_fallback = false;
  QString fallback_reason;
  bool engine_fallback = false;
  QString engine_fallback_reason;
};

QString appConfigRoot() {
  auto path = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  if (path.isEmpty()) {
    path = QDir::home().filePath(QStringLiteral(".gmssh-client"));
  }
  return path;
}

QString appDataRoot() {
  auto path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  if (path.isEmpty()) {
    path = QDir::home().filePath(QStringLiteral(".gmssh-client"));
  }
  return path;
}

QString sanitize(const QString& text, int max_chars = 900) {
  auto value = text;
  value.replace(QStringLiteral("\r"), QStringLiteral(""));
  value.replace(QStringLiteral("\n"), QStringLiteral("\\n"));
  if (value.size() > max_chars) {
    value = value.left(max_chars) + QStringLiteral("...");
  }
  return value;
}

QString modeText(AlgorithmMode mode) {
  switch (mode) {
    case AlgorithmMode::Auto:
      return QStringLiteral("auto");
    case AlgorithmMode::GmOnly:
      return QStringLiteral("gm_only");
    case AlgorithmMode::StandardOnly:
      return QStringLiteral("standard_only");
  }
  return QStringLiteral("unknown");
}

QString policyText(GmHostSignaturePolicy policy) {
  return policy == GmHostSignaturePolicy::CompatibilityBypass
             ? QStringLiteral("old_gm_adaptation")
             : QStringLiteral("strict");
}

std::optional<ConnectionProfile> findProfile(
    const QVector<ConnectionProfile>& profiles,
    const QString& name) {
  for (const auto& profile : profiles) {
    if (profile.name == name) {
      return profile;
    }
  }
  return std::nullopt;
}

QVector<ConnectionProfile> loadProfiles(const QString& path, QString* error) {
  ProfileRepository repository(path);
  return repository.loadAll(error);
}

SessionSecrets loadSecrets(
    const QString& credentials_path,
    const QString& profile_name,
    QString* error) {
  CredentialStore store(credentials_path);
  const auto loaded = store.loadPassword(profile_name);
  if (!loaded.ok) {
    if (error != nullptr) {
      *error = loaded.error;
    }
    return {};
  }

  SessionSecrets secrets;
  secrets.password = loaded.value;
  return secrets;
}

bool executableOk(const QString& path) {
  if (path.trimmed().isEmpty()) {
    return false;
  }
  const QFileInfo info(path);
  return info.exists() && info.isFile() && info.isExecutable();
}

SshEngineAdapter makeAdapter(const RuntimeConfig& config) {
  SshEngineAdapter adapter;
  adapter.setSshBinaryPath(config.modern_ssh);
  adapter.setSftpBinaryPath(config.modern_sftp);
  adapter.setLegacySshBinaryPath(config.legacy_ssh);
  adapter.setLegacySftpBinaryPath(config.legacy_sftp);
  adapter.setKnownHostsPath(config.known_hosts_path);
  return adapter;
}

void cleanupPlan(const SshLaunchPlan& plan) {
  for (const auto& path : plan.cleanup_files) {
    QFile::remove(path);
  }
}

OperationResult runTerminalCommand(
    const RuntimeConfig& config,
    const ConnectionProfile& profile,
    const SessionSecrets& secrets,
    GmHostSignaturePolicy policy) {
  auto adapter = makeAdapter(config);
  adapter.setGmHostSignaturePolicy(policy);
  auto plan = adapter.prepareLaunch(profile, secrets);

  OperationResult result;
  result.selected_mode = modeText(plan.selected_mode);
  result.algorithm_fallback = plan.fallback_used;
  result.fallback_reason = plan.fallback_reason;
  result.engine_fallback = plan.engine_fallback_used;
  result.engine_fallback_reason = plan.engine_fallback_reason;

  if (!plan.ok) {
    result.detail = plan.error;
    return result;
  }

  QProcess process;
  auto args = plan.arguments;
  args << QStringLiteral("printf GMSSH_MATRIX_TERMINAL_OK");
  process.setProgram(plan.program);
  process.setArguments(args);
  process.setProcessEnvironment(plan.environment);
  process.start();
  if (!process.waitForStarted(6000)) {
    result.detail = QStringLiteral("failed to start ssh: %1").arg(process.errorString());
    cleanupPlan(plan);
    return result;
  }

  if (!process.waitForFinished(kProcessTimeoutMs)) {
    process.kill();
    process.waitForFinished(2000);
    result.detail = QStringLiteral("terminal command timed out");
    cleanupPlan(plan);
    return result;
  }

  const auto stdout_text = QString::fromUtf8(process.readAllStandardOutput());
  const auto stderr_text = QString::fromUtf8(process.readAllStandardError());
  result.ok = process.exitCode() == 0 &&
              stdout_text.contains(QStringLiteral("GMSSH_MATRIX_TERMINAL_OK"));
  result.detail = QStringLiteral("exit=%1 stdout=%2 stderr=%3")
                      .arg(process.exitCode())
                      .arg(sanitize(stdout_text))
                      .arg(sanitize(stderr_text));
  cleanupPlan(plan);
  return result;
}

OperationResult runSftpList(
    const RuntimeConfig& config,
    const ConnectionProfile& profile,
    const SessionSecrets& secrets,
    GmHostSignaturePolicy policy) {
  auto adapter = makeAdapter(config);
  adapter.setGmHostSignaturePolicy(policy);
  const auto sftp = adapter.runSftpBatch(
      profile,
      secrets,
      {QStringLiteral("pwd"), QStringLiteral("ls -la .")},
      kProcessTimeoutMs);

  OperationResult result;
  result.ok = sftp.ok;
  result.selected_mode = modeText(sftp.selected_mode);
  result.algorithm_fallback = sftp.fallback_used;
  result.fallback_reason = sftp.fallback_reason;
  result.engine_fallback = sftp.engine_fallback_used;
  result.engine_fallback_reason = sftp.engine_fallback_reason;
  result.detail = QStringLiteral("exit=%1 error=%2 stdout=%3 stderr=%4")
                      .arg(sftp.exit_code)
                      .arg(sanitize(sftp.error))
                      .arg(sanitize(sftp.std_out))
                      .arg(sanitize(sftp.std_err));
  return result;
}

int reserveLocalPort() {
  QTcpServer server;
  if (!server.listen(QHostAddress::LocalHost, 0)) {
    return 0;
  }
  const auto port = static_cast<int>(server.serverPort());
  server.close();
  return port;
}

bool waitForForwardedBanner(int port, QString* detail) {
  const auto deadline = QDeadlineTimer(kForwardTimeoutMs);
  while (!deadline.hasExpired()) {
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, static_cast<quint16>(port));
    if (socket.waitForConnected(700)) {
      socket.write("SSH-2.0-gmssh-matrix\r\n");
      socket.waitForBytesWritten(1000);
      if (socket.waitForReadyRead(1200)) {
        const auto banner = QString::fromUtf8(socket.readAll());
        if (detail != nullptr) {
          *detail = QStringLiteral("banner=%1").arg(sanitize(banner));
        }
        return banner.startsWith(QStringLiteral("SSH-"));
      }
      if (detail != nullptr) {
        *detail = QStringLiteral("local forwarding listener accepted connection; no banner before timeout");
      }
      return true;
    }
    QThread::msleep(250);
  }

  if (detail != nullptr) {
    *detail = QStringLiteral("forwarded local port did not open");
  }
  return false;
}

OperationResult runForwardingProbe(
    const RuntimeConfig& config,
    ConnectionProfile profile,
    const SessionSecrets& secrets,
    GmHostSignaturePolicy policy) {
  const int local_port = reserveLocalPort();
  OperationResult result;
  if (local_port == 0) {
    result.detail = QStringLiteral("failed to reserve local port");
    return result;
  }

  ForwardRule rule;
  rule.type = ForwardType::Local;
  rule.bind_port_or_path = QStringLiteral("127.0.0.1:%1").arg(local_port);
  rule.target_addr = QStringLiteral("127.0.0.1");
  rule.target_port_or_path = QStringLiteral("22");
  profile.forwarding_rules = {rule};

  auto adapter = makeAdapter(config);
  adapter.setGmHostSignaturePolicy(policy);
  auto plan = adapter.prepareLaunch(profile, secrets);
  result.selected_mode = modeText(plan.selected_mode);
  result.algorithm_fallback = plan.fallback_used;
  result.fallback_reason = plan.fallback_reason;
  result.engine_fallback = plan.engine_fallback_used;
  result.engine_fallback_reason = plan.engine_fallback_reason;

  if (!plan.ok) {
    result.detail = plan.error;
    return result;
  }

  auto args = plan.arguments;
  args.removeAll(QStringLiteral("-tt"));
  if (!args.isEmpty()) {
    args.insert(args.size() - 1, QStringLiteral("-N"));
    args.insert(args.size() - 1, QStringLiteral("-o"));
    args.insert(args.size() - 1, QStringLiteral("ExitOnForwardFailure=yes"));
  }

  QProcess process;
  process.setProgram(plan.program);
  process.setArguments(args);
  process.setProcessEnvironment(plan.environment);
  process.start();
  if (!process.waitForStarted(6000)) {
    result.detail = QStringLiteral("failed to start forwarding ssh: %1").arg(process.errorString());
    cleanupPlan(plan);
    return result;
  }

  QString banner_detail;
  result.ok = waitForForwardedBanner(local_port, &banner_detail);
  const auto stderr_text = QString::fromUtf8(process.readAllStandardError());
  result.detail = QStringLiteral("local_port=%1 %2 stderr=%3")
                      .arg(local_port)
                      .arg(banner_detail)
                      .arg(sanitize(stderr_text));

  process.kill();
  process.waitForFinished(3000);
  cleanupPlan(plan);
  return result;
}

QJsonObject opToJson(const OperationResult& op, bool expected_ok) {
  const bool verdict = op.ok == expected_ok;
  return QJsonObject{
      {QStringLiteral("ok"), op.ok},
      {QStringLiteral("expected_ok"), expected_ok},
      {QStringLiteral("verdict"), verdict ? QStringLiteral("pass") : QStringLiteral("fail")},
      {QStringLiteral("selected_mode"), op.selected_mode},
      {QStringLiteral("algorithm_fallback"), op.algorithm_fallback},
      {QStringLiteral("fallback_reason"), op.fallback_reason},
      {QStringLiteral("engine_fallback"), op.engine_fallback},
      {QStringLiteral("engine_fallback_reason"), op.engine_fallback_reason},
      {QStringLiteral("detail"), op.detail},
  };
}

bool operationVerdict(const OperationResult& op, bool expected_ok) {
  return op.ok == expected_ok;
}

QJsonObject caseToJson(
    const MatrixCase& test_case,
    const OperationResult& terminal,
    const OperationResult& sftp,
    const OperationResult& forwarding) {
  const bool passed = operationVerdict(terminal, test_case.expect_terminal_ok) &&
                      operationVerdict(sftp, test_case.expect_sftp_ok) &&
                      operationVerdict(forwarding, test_case.expect_forward_ok);
  return QJsonObject{
      {QStringLiteral("case"), test_case.name},
      {QStringLiteral("profile"), test_case.source_profile},
      {QStringLiteral("port"), test_case.port},
      {QStringLiteral("mode"), modeText(test_case.mode)},
      {QStringLiteral("policy"), policyText(test_case.policy)},
      {QStringLiteral("verdict"), passed ? QStringLiteral("pass") : QStringLiteral("fail")},
      {QStringLiteral("terminal"), opToJson(terminal, test_case.expect_terminal_ok)},
      {QStringLiteral("sftp"), opToJson(sftp, test_case.expect_sftp_ok)},
      {QStringLiteral("forwarding"), opToJson(forwarding, test_case.expect_forward_ok)},
  };
}

QVector<MatrixCase> defaultCases() {
  return {
      {QStringLiteral("kylin-auto-old-gm-adaptation"),
       QStringLiteral("麒麟 V10 SP3"),
       22,
       AlgorithmMode::Auto,
       GmHostSignaturePolicy::CompatibilityBypass,
       true,
       true,
       true},
      {QStringLiteral("kylin-gm-only-old-gm-adaptation"),
       QStringLiteral("麒麟 V10 SP3"),
       22,
       AlgorithmMode::GmOnly,
       GmHostSignaturePolicy::CompatibilityBypass,
       true,
       true,
       true},
      {QStringLiteral("kylin-standard-only-expected-fail"),
       QStringLiteral("麒麟 V10 SP3"),
       22,
       AlgorithmMode::StandardOnly,
       GmHostSignaturePolicy::CompatibilityBypass,
       false,
       false,
       false},
      {QStringLiteral("openeuler-gm-auto"),
       QStringLiteral("open Euler"),
       2222,
       AlgorithmMode::Auto,
       GmHostSignaturePolicy::Strict,
       true,
       true,
       true},
      {QStringLiteral("openeuler-gm-only"),
       QStringLiteral("open Euler"),
       2222,
       AlgorithmMode::GmOnly,
       GmHostSignaturePolicy::Strict,
       true,
       true,
       true},
      {QStringLiteral("openeuler-gm-standard-only-expected-fail"),
       QStringLiteral("open Euler"),
       2222,
       AlgorithmMode::StandardOnly,
       GmHostSignaturePolicy::Strict,
       false,
       false,
       false},
      {QStringLiteral("openeuler-standard-auto"),
       QStringLiteral("open Euler"),
       22,
       AlgorithmMode::Auto,
       GmHostSignaturePolicy::Strict,
       true,
       true,
       true},
      {QStringLiteral("openeuler-standard-only"),
       QStringLiteral("open Euler"),
       22,
       AlgorithmMode::StandardOnly,
       GmHostSignaturePolicy::Strict,
       true,
       true,
       true},
      {QStringLiteral("openeuler-standard-gm-only-expected-fail"),
       QStringLiteral("open Euler"),
       22,
       AlgorithmMode::GmOnly,
       GmHostSignaturePolicy::Strict,
       false,
       false,
       false},
  };
}

void printCaseSummary(const QJsonObject& object) {
  const auto name = object.value(QStringLiteral("case")).toString();
  const auto verdict = object.value(QStringLiteral("verdict")).toString();
  const auto terminal =
      object.value(QStringLiteral("terminal")).toObject().value(QStringLiteral("verdict")).toString();
  const auto sftp =
      object.value(QStringLiteral("sftp")).toObject().value(QStringLiteral("verdict")).toString();
  const auto forwarding = object.value(QStringLiteral("forwarding"))
                              .toObject()
                              .value(QStringLiteral("verdict"))
                              .toString();
  std::cout << verdict.toStdString() << " " << name.toStdString()
            << " terminal=" << terminal.toStdString()
            << " sftp=" << sftp.toStdString()
            << " forwarding=" << forwarding.toStdString() << "\n"
            << std::flush;
}

}  // namespace

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  app.setApplicationName(QStringLiteral("gmssh-client"));
  app.setOrganizationName(QStringLiteral("internal"));

  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("GMSSH P1 interoperability matrix probe"));
  parser.addHelpOption();
  const QCommandLineOption profiles_opt(
      QStringLiteral("profiles"),
      QStringLiteral("Path to profiles.json"),
      QStringLiteral("path"),
      QDir(appConfigRoot()).filePath(QStringLiteral("profiles.json")));
  const QCommandLineOption credentials_opt(
      QStringLiteral("credentials"),
      QStringLiteral("Path to credentials.json"),
      QStringLiteral("path"),
      QDir(appConfigRoot()).filePath(QStringLiteral("credentials.json")));
  const QCommandLineOption known_hosts_opt(
      QStringLiteral("known-hosts"),
      QStringLiteral("Known hosts file for matrix probes"),
      QStringLiteral("path"),
      QDir(appDataRoot()).filePath(QStringLiteral("matrix_known_hosts")));
  const QCommandLineOption modern_ssh_opt(
      QStringLiteral("modern-ssh"), QStringLiteral("Modern SSH engine"), QStringLiteral("path"));
  const QCommandLineOption modern_sftp_opt(
      QStringLiteral("modern-sftp"), QStringLiteral("Modern SFTP engine"), QStringLiteral("path"));
  const QCommandLineOption legacy_ssh_opt(
      QStringLiteral("legacy-ssh"), QStringLiteral("Legacy SSH engine"), QStringLiteral("path"));
  const QCommandLineOption legacy_sftp_opt(
      QStringLiteral("legacy-sftp"), QStringLiteral("Legacy SFTP engine"), QStringLiteral("path"));
  const QCommandLineOption output_opt(
      QStringLiteral("output"), QStringLiteral("Write JSON report to path"), QStringLiteral("path"));
  parser.addOptions({
      profiles_opt,
      credentials_opt,
      known_hosts_opt,
      modern_ssh_opt,
      modern_sftp_opt,
      legacy_ssh_opt,
      legacy_sftp_opt,
      output_opt,
  });
  parser.process(app);

  RuntimeConfig config;
  config.profiles_path = parser.value(profiles_opt);
  config.credentials_path = parser.value(credentials_opt);
  config.known_hosts_path = parser.value(known_hosts_opt);
  config.modern_ssh = parser.value(modern_ssh_opt);
  config.modern_sftp = parser.value(modern_sftp_opt);
  config.legacy_ssh = parser.value(legacy_ssh_opt);
  config.legacy_sftp = parser.value(legacy_sftp_opt);
  config.output_json_path = parser.value(output_opt);

  if (!executableOk(config.modern_ssh) || !executableOk(config.modern_sftp)) {
    std::cerr << "modern SSH/SFTP engine is missing or not executable\n";
    return 2;
  }
  if (!executableOk(config.legacy_ssh) || !executableOk(config.legacy_sftp)) {
    std::cerr << "legacy SSH/SFTP engine is missing or not executable\n";
    return 2;
  }

  QFileInfo known_hosts_info(config.known_hosts_path);
  QDir().mkpath(known_hosts_info.absolutePath());

  QString load_error;
  const auto profiles = loadProfiles(config.profiles_path, &load_error);
  if (!load_error.isEmpty()) {
    std::cerr << "failed to load profiles: " << load_error.toStdString() << "\n";
    return 2;
  }

  QJsonArray case_results;
  bool all_passed = true;

  for (const auto& test_case : defaultCases()) {
    std::cout << "running " << test_case.name.toStdString() << "\n" << std::flush;
    const auto base_profile = findProfile(profiles, test_case.source_profile);
    if (!base_profile.has_value()) {
      QJsonObject missing{
          {QStringLiteral("case"), test_case.name},
          {QStringLiteral("profile"), test_case.source_profile},
          {QStringLiteral("verdict"), QStringLiteral("fail")},
          {QStringLiteral("error"), QStringLiteral("profile not found")},
      };
      printCaseSummary(missing);
      case_results.append(missing);
      all_passed = false;
      continue;
    }

    QString secret_error;
    const auto secrets = loadSecrets(config.credentials_path, test_case.source_profile, &secret_error);
    if (!secret_error.isEmpty()) {
      QJsonObject missing{
          {QStringLiteral("case"), test_case.name},
          {QStringLiteral("profile"), test_case.source_profile},
          {QStringLiteral("verdict"), QStringLiteral("fail")},
          {QStringLiteral("error"), QStringLiteral("credential not available: %1").arg(secret_error)},
      };
      printCaseSummary(missing);
      case_results.append(missing);
      all_passed = false;
      continue;
    }

    auto profile = base_profile.value();
    profile.port = test_case.port;
    profile.algorithm_mode = test_case.mode;

    const auto terminal = runTerminalCommand(config, profile, secrets, test_case.policy);
    const auto sftp = runSftpList(config, profile, secrets, test_case.policy);
    const auto forwarding = runForwardingProbe(config, profile, secrets, test_case.policy);
    const auto object = caseToJson(test_case, terminal, sftp, forwarding);
    printCaseSummary(object);
    case_results.append(object);
    all_passed = all_passed && object.value(QStringLiteral("verdict")).toString() == QStringLiteral("pass");
  }

  QJsonObject report{
      {QStringLiteral("verdict"), all_passed ? QStringLiteral("pass") : QStringLiteral("fail")},
      {QStringLiteral("profiles_path"), config.profiles_path},
      {QStringLiteral("known_hosts_path"), config.known_hosts_path},
      {QStringLiteral("modern_ssh"), config.modern_ssh},
      {QStringLiteral("modern_sftp"), config.modern_sftp},
      {QStringLiteral("legacy_ssh"), config.legacy_ssh},
      {QStringLiteral("legacy_sftp"), config.legacy_sftp},
      {QStringLiteral("cases"), case_results},
  };

  if (!config.output_json_path.trimmed().isEmpty()) {
    QFileInfo output_info(config.output_json_path);
    QDir().mkpath(output_info.absolutePath());
    QFile output(config.output_json_path);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Text)) {
      std::cerr << "failed to write output JSON\n";
      return 2;
    }
    output.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
  }

  return all_passed ? 0 : 1;
}
