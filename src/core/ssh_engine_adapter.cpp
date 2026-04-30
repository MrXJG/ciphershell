#include "core/ssh_engine_adapter.h"

#include <QDir>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QStringDecoder>
#include <QTemporaryDir>
#include <QTemporaryFile>

namespace gmssh {
namespace {

constexpr auto kEcgmHostSigBypassEnv = "GMSSH_ECGM_HOSTSIG_BYPASS";

bool stderrSuggestsCompatibility(const QString& stderr_text) {
  return stderr_text.contains(
             QStringLiteral("host signature verify bypass enabled"), Qt::CaseInsensitive) ||
         stderr_text.contains(
             QStringLiteral("legacy GM host-signature adaptation enabled"),
             Qt::CaseInsensitive);
}

bool stderrIndicatesAuthBoundary(const QString& stderr_text) {
  static const QStringList kSignals = {
      QStringLiteral("Permission denied"),
      QStringLiteral("Authentication failed"),
      QStringLiteral("Too many authentication failures"),
      QStringLiteral("Host key verification failed"),
  };

  for (const auto& signal : kSignals) {
    if (stderr_text.contains(signal, Qt::CaseInsensitive)) {
      return true;
    }
  }

  return false;
}

bool stderrIndicatesStrictPolicyBlocked(const QString& stderr_text) {
  return stderr_text.contains(
      QStringLiteral("strict_policy_blocked_compatibility_bypass"),
      Qt::CaseInsensitive);
}

QString appStateDir() {
  auto path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  if (path.isEmpty()) {
    path = QDir::home().filePath(QStringLiteral(".gmssh-client"));
  }
  QDir().mkpath(path);
  return path;
}

QString writeAskPassScript() {
  const auto script_path =
#if defined(Q_OS_WIN)
      QDir(appStateDir()).filePath(QStringLiteral("askpass-%1.cmd")
                                       .arg(QRandomGenerator::global()->generate64()));
#else
      QDir(appStateDir()).filePath(QStringLiteral("askpass-%1.sh")
                                       .arg(QRandomGenerator::global()->generate64()));
#endif

  QFile file(script_path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
    return {};
  }

#if defined(Q_OS_WIN)
  file.write("@echo off\r\n");
  file.write("echo %GMSSH_ASKPASS_PASSWORD%\r\n");
#else
  file.write("#!/bin/sh\n");
  file.write("printf '%s\\n' \"$GMSSH_ASKPASS_PASSWORD\"\n");
#endif
  file.close();
  file.setPermissions(
      QFileDevice::ReadOwner |
      QFileDevice::WriteOwner |
      QFileDevice::ExeOwner);
  return script_path;
}

QString decodeStderr(const QByteArray& bytes) {
  return QString::fromUtf8(bytes.constData(), bytes.size());
}

bool stderrIndicatesHostKeyChanged(const QString& stderr_text) {
  return stderr_text.contains(
             QStringLiteral("REMOTE HOST IDENTIFICATION HAS CHANGED"),
             Qt::CaseInsensitive) ||
         (stderr_text.contains(QStringLiteral("Host key verification failed"), Qt::CaseInsensitive) &&
          stderr_text.contains(QStringLiteral("Offending"), Qt::CaseInsensitive));
}

bool runSshKeygenRemove(const QString& known_hosts_path, const QString& host_spec) {
  if (known_hosts_path.trimmed().isEmpty() || host_spec.trimmed().isEmpty()) {
    return false;
  }

  QProcess process;
  process.setProgram(QStringLiteral("ssh-keygen"));
  process.setArguments({
      QStringLiteral("-f"),
      known_hosts_path,
      QStringLiteral("-R"),
      host_spec,
  });
  process.start();
  if (!process.waitForFinished(5000)) {
    return false;
  }

  return process.exitCode() == 0;
}

bool executableAvailable(const QString& program) {
  const auto trimmed = program.trimmed();
  if (trimmed.isEmpty()) {
    return false;
  }

  if (trimmed.contains(QChar::fromLatin1('/'))) {
    const QFileInfo info(trimmed);
    return info.exists() && info.isFile() && info.isExecutable();
  }

  return !QStandardPaths::findExecutable(trimmed).isEmpty();
}

bool sftpOutputIndicatesCommandFailure(const QString& output) {
  static const QStringList kSignals = {
      QStringLiteral("Couldn't "),
      QStringLiteral("No such file"),
      QStringLiteral("not found"),
      QStringLiteral("Permission denied"),
      QStringLiteral("Failure"),
      QStringLiteral("not a regular file"),
      QStringLiteral("not a directory"),
      QStringLiteral("Invalid flag"),
      QStringLiteral("Invalid command"),
  };

  for (const auto& signal : kSignals) {
    if (output.contains(signal, Qt::CaseInsensitive)) {
      return true;
    }
  }

  return false;
}

QString enginePreferenceKey(
    const ConnectionProfile& profile,
    GmHostSignaturePolicy policy) {
  return QStringLiteral("%1|%2|%3|%4|%5")
      .arg(profile.host)
      .arg(profile.port)
      .arg(profile.username)
      .arg(toString(profile.algorithm_mode))
      .arg(policy == GmHostSignaturePolicy::CompatibilityBypass
               ? QStringLiteral("compat")
               : QStringLiteral("strict"));
}

QString modernToLegacyFallbackReason(const QString& stderr_text) {
  if (SshCommandBuilder::stderrIndicatesMacIncorrect(stderr_text)) {
    return QStringLiteral("gm_probe_mac_incorrect_modern_to_legacy");
  }

  if (SshCommandBuilder::stderrIndicatesVerifyKexInternalError(stderr_text)) {
    return QStringLiteral("gm_probe_verify_kex_internal_modern_to_legacy");
  }

  if (stderr_text.contains(QStringLiteral("unexpected internal error"), Qt::CaseInsensitive)) {
    return QStringLiteral("gm_probe_internal_error_modern_to_legacy");
  }

  return {};
}

QString legacyToModernFallbackReason(const QString& stderr_text) {
  if (SshCommandBuilder::stderrIndicatesVerifyKexInternalError(stderr_text)) {
    return QStringLiteral("gm_probe_verify_kex_internal_legacy_to_modern");
  }

  return {};
}

QString sftpControlPath(
    const ConnectionProfile& profile,
    const QString& ssh_program,
    AlgorithmCandidate candidate,
    GmHostSignaturePolicy policy) {
#if defined(Q_OS_WIN)
  Q_UNUSED(profile);
  Q_UNUSED(ssh_program);
  Q_UNUSED(candidate);
  Q_UNUSED(policy);
  return {};
#else
  const auto material = QStringLiteral("%1|%2|%3|%4|%5|%6")
                            .arg(profile.host)
                            .arg(profile.port)
                            .arg(profile.username, ssh_program)
                            .arg(candidate == AlgorithmCandidate::Gm
                                     ? QStringLiteral("gm")
                                     : QStringLiteral("standard"))
                            .arg(policy == GmHostSignaturePolicy::CompatibilityBypass
                                     ? QStringLiteral("old-gm-adaptation")
                                     : QStringLiteral("strict"));
  const auto digest =
      QCryptographicHash::hash(material.toUtf8(), QCryptographicHash::Sha256).toHex().left(24);
  return QDir::temp().filePath(QStringLiteral("gmssh-sftp-%1").arg(QString::fromLatin1(digest)));
#endif
}

}  // namespace

SshEngineAdapter::SshEngineAdapter(AuditLogger* audit_logger)
    : ssh_binary_path_(QStringLiteral("ssh")),
      sftp_binary_path_(QStringLiteral("sftp")),
      legacy_ssh_binary_path_(),
      legacy_sftp_binary_path_(),
      known_hosts_path_(QDir(appStateDir()).filePath(QStringLiteral("known_hosts"))),
      audit_logger_(audit_logger) {
  const QFileInfo info(known_hosts_path_);
  QDir().mkpath(info.absolutePath());
}

void SshEngineAdapter::setSshBinaryPath(QString path) {
  ssh_binary_path_ = std::move(path);
}

void SshEngineAdapter::setSftpBinaryPath(QString path) {
  sftp_binary_path_ = std::move(path);
}

void SshEngineAdapter::setLegacySshBinaryPath(QString path) {
  legacy_ssh_binary_path_ = std::move(path);
}

void SshEngineAdapter::setLegacySftpBinaryPath(QString path) {
  legacy_sftp_binary_path_ = std::move(path);
}

void SshEngineAdapter::setKnownHostsPath(QString path) {
  known_hosts_path_ = std::move(path);
  const QFileInfo info(known_hosts_path_);
  QDir().mkpath(info.absolutePath());
}

bool SshEngineAdapter::clearHostKeyEntries(const ConnectionProfile& profile) const {
  bool removed = false;
  removed = runSshKeygenRemove(known_hosts_path_, profile.host) || removed;

  if (profile.port > 0) {
    const auto with_port = QStringLiteral("[%1]:%2").arg(profile.host).arg(profile.port);
    removed = runSshKeygenRemove(known_hosts_path_, with_port) || removed;
  }

  return removed;
}

const QString& SshEngineAdapter::sshBinaryPath() const {
  return ssh_binary_path_;
}

const QString& SshEngineAdapter::sftpBinaryPath() const {
  return sftp_binary_path_;
}

const QString& SshEngineAdapter::legacySshBinaryPath() const {
  return legacy_ssh_binary_path_;
}

const QString& SshEngineAdapter::legacySftpBinaryPath() const {
  return legacy_sftp_binary_path_;
}

void SshEngineAdapter::setGmHostSignaturePolicy(GmHostSignaturePolicy policy) {
  gm_host_signature_policy_ = policy;
}

GmHostSignaturePolicy SshEngineAdapter::gmHostSignaturePolicy() const {
  return gm_host_signature_policy_;
}

QProcessEnvironment SshEngineAdapter::runtimeEnvironment() const {
  auto env = QProcessEnvironment::systemEnvironment();
  env.insert(
      QString::fromLatin1(kEcgmHostSigBypassEnv),
      gm_host_signature_policy_ == GmHostSignaturePolicy::CompatibilityBypass
          ? QStringLiteral("1")
          : QStringLiteral("0"));
  return env;
}

AlgorithmCandidate SshEngineAdapter::chooseAlgorithmCandidate(
    const ConnectionProfile& profile,
    QString* reason,
    bool* fallback_used,
    const QString& ssh_program) const {
  *fallback_used = false;
  reason->clear();

  if (profile.algorithm_mode == AlgorithmMode::StandardOnly) {
    return AlgorithmCandidate::Standard;
  }

  if (profile.algorithm_mode == AlgorithmMode::GmOnly) {
    return AlgorithmCandidate::Gm;
  }

  const auto gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, ssh_program);
  if (gm_probe.compatible) {
    return AlgorithmCandidate::Gm;
  }

  if (stderrIndicatesStrictPolicyBlocked(gm_probe.stderr_text)) {
    *fallback_used = true;
    *reason = QStringLiteral("strict_policy_blocked_compatibility_bypass");
    return AlgorithmCandidate::Standard;
  }

  if (SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(gm_probe.stderr_text)) {
    *fallback_used = true;
    *reason = QStringLiteral("gm_probe_runtime_incompatible");
    return AlgorithmCandidate::Standard;
  }

  if (gm_probe.algorithm_mismatch) {
    *fallback_used = true;
    *reason = SshCommandBuilder::stderrIndicatesLocalGmOptionUnsupported(gm_probe.stderr_text)
                  ? QStringLiteral("local_client_gm_option_unsupported")
                  : QStringLiteral("gm_probe_algorithm_mismatch");
    return AlgorithmCandidate::Standard;
  }

  return AlgorithmCandidate::Gm;
}

SshEngineAdapter::ProbeOutcome SshEngineAdapter::probeCandidate(
    const ConnectionProfile& profile,
    AlgorithmCandidate candidate,
    const QString& ssh_program) const {
  auto run_probe_once = [&]() -> ProbeOutcome {
    ProbeOutcome outcome;

    QProcess process;
    process.setProgram(
        ssh_program.trimmed().isEmpty()
            ? resolveBinary(ssh_binary_path_, QStringLiteral("ssh"))
            : ssh_program);
    process.setArguments(
        SshCommandBuilder::buildProbeArgs(profile, known_hosts_path_, candidate));
    process.setProcessEnvironment(runtimeEnvironment());
    process.start();

    if (!process.waitForStarted(6000)) {
      outcome.compatible = false;
      outcome.stderr_text = QStringLiteral("probe process failed to start");
      return outcome;
    }

    process.waitForFinished(12000);

    outcome.exit_code = process.exitCode();
    outcome.stderr_text = decodeStderr(process.readAllStandardError());

    const bool mismatch =
        SshCommandBuilder::stderrIndicatesAlgorithmMismatch(outcome.stderr_text);
    outcome.algorithm_mismatch = mismatch;

    if (SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(outcome.stderr_text)) {
      outcome.compatible = false;
      outcome.transport_reachable = true;
      return outcome;
    }

    if (stderrSuggestsCompatibility(outcome.stderr_text)) {
      outcome.transport_reachable = true;
      if (gm_host_signature_policy_ == GmHostSignaturePolicy::Strict) {
        outcome.compatible = false;
        outcome.stderr_text.append(
            QStringLiteral("\nstrict_policy_blocked_compatibility_bypass unexpected internal error"));
        return outcome;
      }
      outcome.compatible = true;
      return outcome;
    }

    if (stderrIndicatesAuthBoundary(outcome.stderr_text)) {
      outcome.compatible = true;
      outcome.transport_reachable = true;
      return outcome;
    }

    if (outcome.exit_code == 0) {
      outcome.compatible = true;
      outcome.transport_reachable = true;
      return outcome;
    }

    if (mismatch) {
      outcome.compatible = false;
      return outcome;
    }

    outcome.transport_reachable =
        !outcome.stderr_text.contains(QStringLiteral("No route to host"), Qt::CaseInsensitive) &&
        !outcome.stderr_text.contains(QStringLiteral("Connection timed out"), Qt::CaseInsensitive);

    return outcome;
  };

  auto outcome = run_probe_once();
  if (!stderrIndicatesHostKeyChanged(outcome.stderr_text)) {
    return outcome;
  }

  const bool removed = clearHostKeyEntries(profile);
  if (audit_logger_ != nullptr) {
    audit_logger_->logEvent(
        QStringLiteral("known_hosts_repair"),
        QJsonObject{
            {QStringLiteral("profile"), profile.name},
            {QStringLiteral("host"), profile.host},
            {QStringLiteral("port"), profile.port},
            {QStringLiteral("removed"), removed},
        });
  }

  if (!removed) {
    return outcome;
  }

  return run_probe_once();
}

SshEngineAdapter::IdentityMaterial SshEngineAdapter::prepareIdentityMaterial(
    const ConnectionProfile& profile,
    const SessionSecrets& secrets) const {
  IdentityMaterial material;

  if (profile.auth_method == AuthMethod::Sm2Key) {
    material.identity_file = profile.key_path;
    return material;
  }

  if (profile.auth_method == AuthMethod::OpenSshCert) {
    material.identity_file = profile.key_path;
    material.certificate_file = profile.cert_path;
    return material;
  }

  if (profile.auth_method == AuthMethod::X509Sm2Cert) {
    if (!profile.pfx_path.trimmed().isEmpty()) {
      const auto output_path =
          QDir(appStateDir()).filePath(QStringLiteral("pfx-%1.pem")
                                           .arg(QRandomGenerator::global()->generate64()));

      QProcess process;
      process.setProgram(QStringLiteral("openssl"));
      process.setArguments({
          QStringLiteral("pkcs12"),
          QStringLiteral("-in"),
          profile.pfx_path,
          QStringLiteral("-nodes"),
          QStringLiteral("-out"),
          output_path,
          QStringLiteral("-passin"),
          QStringLiteral("pass:%1").arg(secrets.pfx_password),
      });

      process.start();
      if (!process.waitForFinished(8000) || process.exitCode() != 0) {
        material.ok = false;
        material.error = QStringLiteral("failed to convert pfx to pem");
        return material;
      }

      material.identity_file = output_path;
      material.cleanup_files.push_back(output_path);
      return material;
    }

    material.identity_file = profile.key_path;
    material.certificate_file = profile.cert_path;
    return material;
  }

  return material;
}

SshEngineAdapter::AskPassMaterial SshEngineAdapter::prepareAskPass(
    const SessionSecrets& secrets) const {
  AskPassMaterial material;
  material.environment = runtimeEnvironment();

  if (secrets.password.isEmpty()) {
    return material;
  }

  const auto script_path = writeAskPassScript();
  if (script_path.isEmpty()) {
    return material;
  }

  material.cleanup_files.push_back(script_path);
  material.environment.insert(QStringLiteral("SSH_ASKPASS"), script_path);
  material.environment.insert(QStringLiteral("SSH_ASKPASS_REQUIRE"), QStringLiteral("force"));
  material.environment.insert(QStringLiteral("GMSSH_ASKPASS_PASSWORD"), secrets.password);
#if !defined(Q_OS_WIN)
  if (material.environment.value(QStringLiteral("DISPLAY")).isEmpty()) {
    material.environment.insert(QStringLiteral("DISPLAY"), QStringLiteral("gmssh:0"));
  }
#endif

  return material;
}

QString SshEngineAdapter::resolveBinary(
    const QString& candidate_path,
    const QString& fallback_name) {
  if (!candidate_path.trimmed().isEmpty()) {
    return candidate_path;
  }
  return fallback_name;
}

SshLaunchPlan SshEngineAdapter::prepareLaunch(
    const ConnectionProfile& profile,
    const SessionSecrets& secrets) const {
  SshLaunchPlan plan;

  const auto modern_ssh = resolveBinary(ssh_binary_path_, QStringLiteral("ssh"));
  const auto modern_sftp = resolveBinary(sftp_binary_path_, QStringLiteral("sftp"));
  const auto legacy_ssh = legacy_ssh_binary_path_.trimmed();
  const auto legacy_sftp = legacy_sftp_binary_path_.trimmed();

  auto selected_ssh = modern_ssh;
  auto selected_sftp = modern_sftp;
  const auto cache_key = enginePreferenceKey(profile, gm_host_signature_policy_);
  if (profile.algorithm_mode != AlgorithmMode::StandardOnly &&
      engine_preference_cache_.contains(cache_key)) {
    const auto cached = engine_preference_cache_.value(cache_key);
    if (!cached.ssh.trimmed().isEmpty()) {
      selected_ssh = cached.ssh;
      selected_sftp = cached.sftp.trimmed().isEmpty() ? selected_sftp : cached.sftp;
    }
  }

  QString reason;
  bool fallback_used = false;
  auto candidate = chooseAlgorithmCandidate(profile, &reason, &fallback_used, selected_ssh);
  bool engine_fallback_used = false;
  QString engine_fallback_reason;
  QString engine_fallback_from;
  QString engine_fallback_to;

  auto tryEngineFallback = [&](const QString& gm_probe_stderr) -> bool {
    QString alternate_ssh;
    QString alternate_sftp;
    QString fallback_reason;

    if (selected_ssh == modern_ssh && !legacy_ssh.isEmpty()) {
      fallback_reason = modernToLegacyFallbackReason(gm_probe_stderr);
      if (fallback_reason.isEmpty()) {
        return false;
      }
      alternate_ssh = legacy_ssh;
      alternate_sftp = legacy_sftp.isEmpty() ? selected_sftp : legacy_sftp;
    } else if (selected_ssh == legacy_ssh && !modern_ssh.isEmpty()) {
      fallback_reason = legacyToModernFallbackReason(gm_probe_stderr);
      if (fallback_reason.isEmpty()) {
        return false;
      }
      alternate_ssh = modern_ssh;
      alternate_sftp = modern_sftp;
    } else {
      return false;
    }

    if (alternate_ssh.trimmed().isEmpty() || alternate_ssh == selected_ssh) {
      return false;
    }

    const auto alternate_probe = probeCandidate(profile, AlgorithmCandidate::Gm, alternate_ssh);
    if (!alternate_probe.compatible) {
      return false;
    }

    engine_fallback_used = true;
    engine_fallback_reason = fallback_reason;
    engine_fallback_from = selected_ssh;
    engine_fallback_to = alternate_ssh;
    selected_ssh = alternate_ssh;
    selected_sftp = alternate_sftp;
    engine_preference_cache_.insert(cache_key, EnginePreference{selected_ssh, selected_sftp});
    candidate = AlgorithmCandidate::Gm;
    fallback_used = false;
    reason.clear();
    return true;
  };

  if (profile.algorithm_mode == AlgorithmMode::Auto &&
      reason == QStringLiteral("gm_probe_runtime_incompatible")) {
    const auto gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    tryEngineFallback(gm_probe.stderr_text);
  }

  if (profile.algorithm_mode == AlgorithmMode::Auto &&
      fallback_used &&
      (reason == QStringLiteral("local_client_gm_option_unsupported") ||
       reason == QStringLiteral("strict_policy_blocked_compatibility_bypass") ||
       reason == QStringLiteral("gm_probe_runtime_incompatible"))) {
    const auto standard_probe =
        probeCandidate(profile, AlgorithmCandidate::Standard, selected_ssh);
    if (!standard_probe.compatible && standard_probe.algorithm_mismatch) {
      if (reason == QStringLiteral("strict_policy_blocked_compatibility_bypass")) {
        plan.error = QStringLiteral(
            "严格模式已阻断旧版 ecgm 主机签名适配，当前纯国密主机无法在严格模式下建立连接。"
            "如需联调，请在“安全”菜单切换到“国密旧版服务端适配（降低校验强度）”。");
      } else if (reason == QStringLiteral("gm_probe_runtime_incompatible")) {
        plan.error = QStringLiteral(
            "当前国密 SSH 引擎与目标主机的国密实现存在运行时兼容问题。"
            "已完成 ecgm/sm2/sm3/sm4 协商，但在 KEX 阶段后出现 internal error。");
      } else {
        plan.error = QStringLiteral(
            "当前客户端不支持国密算法且服务端为纯国密模式，无法回退常规算法。"
            "请改用国密版 SSH 引擎（支持 ecgm/sm2/sm3/sm4）。");
      }
      return plan;
    }
  }

  if (profile.algorithm_mode == AlgorithmMode::GmOnly) {
    auto gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    if (!gm_probe.compatible &&
        SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(gm_probe.stderr_text) &&
        tryEngineFallback(gm_probe.stderr_text)) {
      gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    }
    if (!gm_probe.compatible && stderrIndicatesStrictPolicyBlocked(gm_probe.stderr_text)) {
      plan.error = QStringLiteral(
          "gm_only 模式失败：严格模式已阻断旧版 ecgm 主机签名适配。"
          "如需联调，请在“安全”菜单切换到“国密旧版服务端适配（降低校验强度）”。");
      return plan;
    }
    if (!gm_probe.compatible &&
        SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(gm_probe.stderr_text)) {
      plan.error = QStringLiteral(
          "gm_only 模式失败：当前国密 SSH 引擎与目标主机的国密实现存在运行时兼容问题。"
          "已协商 ecgm/sm2/sm3/sm4，但在 KEX 阶段后出现 internal error。");
      return plan;
    }
    if (!gm_probe.compatible && gm_probe.algorithm_mismatch) {
      if (SshCommandBuilder::stderrIndicatesLocalGmOptionUnsupported(gm_probe.stderr_text)) {
        plan.error = QStringLiteral(
            "gm_only 模式失败：当前 SSH 引擎不支持国密算法参数，请先构建并使用国密 OpenSSH 引擎。");
      } else {
        plan.error = QStringLiteral("gm_only 模式失败：远端未接受国密算法。");
      }
      return plan;
    }
  }

  const auto identity = prepareIdentityMaterial(profile, secrets);
  if (!identity.ok) {
    plan.error = identity.error;
    return plan;
  }

  const auto ask_pass = prepareAskPass(secrets);

  plan.program = selected_ssh;
  plan.arguments = SshCommandBuilder::buildSessionArgs(
      profile,
      known_hosts_path_,
      candidate,
      identity.identity_file,
      identity.certificate_file);
  plan.environment = ask_pass.environment;
  plan.cleanup_files = identity.cleanup_files;
  plan.cleanup_files.append(ask_pass.cleanup_files);
  plan.selected_mode =
      candidate == AlgorithmCandidate::Gm ? AlgorithmMode::GmOnly : AlgorithmMode::StandardOnly;
  plan.fallback_used = fallback_used;
  plan.fallback_reason = reason;
  plan.gm_hostsig_compatibility_bypass =
      gm_host_signature_policy_ == GmHostSignaturePolicy::CompatibilityBypass;
  plan.engine_fallback_used = engine_fallback_used;
  plan.engine_fallback_reason = engine_fallback_reason;
  plan.engine_fallback_from = engine_fallback_from;
  plan.engine_fallback_to = engine_fallback_to;
  plan.ok = true;

  if (audit_logger_ != nullptr && fallback_used) {
    audit_logger_->logEvent(
        QStringLiteral("algorithm_fallback"),
        QJsonObject{{QStringLiteral("profile"), profile.name},
                    {QStringLiteral("reason"), reason}});
  }
  if (audit_logger_ != nullptr && engine_fallback_used) {
    audit_logger_->logEvent(
        QStringLiteral("engine_fallback"),
        QJsonObject{{QStringLiteral("profile"), profile.name},
                    {QStringLiteral("reason"), engine_fallback_reason},
                    {QStringLiteral("from"), engine_fallback_from},
                    {QStringLiteral("to"), engine_fallback_to}});
  }

  return plan;
}

SftpExecutionResult SshEngineAdapter::runSftpBatch(
    const ConnectionProfile& profile,
    const SessionSecrets& secrets,
    const QStringList& commands,
    int timeout_ms) const {
  SftpExecutionResult result;

  const auto identity = prepareIdentityMaterial(profile, secrets);
  if (!identity.ok) {
    result.error = identity.error;
    return result;
  }

  const auto modern_ssh = resolveBinary(ssh_binary_path_, QStringLiteral("ssh"));
  const auto modern_sftp = resolveBinary(sftp_binary_path_, QStringLiteral("sftp"));
  const auto legacy_ssh = legacy_ssh_binary_path_.trimmed();
  const auto legacy_sftp = legacy_sftp_binary_path_.trimmed();

  auto selected_ssh = modern_ssh;
  auto selected_sftp = modern_sftp;
  const auto cache_key = enginePreferenceKey(profile, gm_host_signature_policy_);
  if (profile.algorithm_mode != AlgorithmMode::StandardOnly &&
      engine_preference_cache_.contains(cache_key)) {
    const auto cached = engine_preference_cache_.value(cache_key);
    if (!cached.ssh.trimmed().isEmpty()) {
      selected_ssh = cached.ssh;
      selected_sftp = cached.sftp.trimmed().isEmpty() ? selected_sftp : cached.sftp;
    }
  }
  QString reason;
  bool fallback_used = false;
  auto candidate = chooseAlgorithmCandidate(profile, &reason, &fallback_used, selected_ssh);
  bool engine_fallback_used = false;
  QString engine_fallback_reason;
  QString engine_fallback_from;
  QString engine_fallback_to;

  auto tryEngineFallback = [&](const QString& gm_probe_stderr) -> bool {
    QString alternate_ssh;
    QString alternate_sftp;
    QString fallback_reason;

    if (selected_ssh == modern_ssh && !legacy_ssh.isEmpty()) {
      fallback_reason = modernToLegacyFallbackReason(gm_probe_stderr);
      if (fallback_reason.isEmpty()) {
        return false;
      }
      alternate_ssh = legacy_ssh;
      alternate_sftp = legacy_sftp.isEmpty() ? selected_sftp : legacy_sftp;
    } else if (selected_ssh == legacy_ssh && !modern_ssh.isEmpty()) {
      fallback_reason = legacyToModernFallbackReason(gm_probe_stderr);
      if (fallback_reason.isEmpty()) {
        return false;
      }
      alternate_ssh = modern_ssh;
      alternate_sftp = modern_sftp;
    } else {
      return false;
    }

    if (alternate_ssh.trimmed().isEmpty() || alternate_ssh == selected_ssh) {
      return false;
    }

    const auto alternate_probe = probeCandidate(profile, AlgorithmCandidate::Gm, alternate_ssh);
    if (!alternate_probe.compatible) {
      return false;
    }

    engine_fallback_used = true;
    engine_fallback_reason = fallback_reason;
    engine_fallback_from = selected_ssh;
    engine_fallback_to = alternate_ssh;
    selected_ssh = alternate_ssh;
    selected_sftp = alternate_sftp;
    engine_preference_cache_.insert(cache_key, EnginePreference{selected_ssh, selected_sftp});
    candidate = AlgorithmCandidate::Gm;
    fallback_used = false;
    reason.clear();
    return true;
  };

  if (profile.algorithm_mode == AlgorithmMode::Auto &&
      reason == QStringLiteral("gm_probe_runtime_incompatible")) {
    const auto gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    tryEngineFallback(gm_probe.stderr_text);
  }

  auto populateResultContext = [&]() {
    result.ssh_program = selected_ssh;
    result.sftp_program = selected_sftp;
    result.selected_mode =
        candidate == AlgorithmCandidate::Gm ? AlgorithmMode::GmOnly : AlgorithmMode::StandardOnly;
    result.fallback_used = fallback_used;
    result.fallback_reason = reason;
    result.engine_fallback_used = engine_fallback_used;
    result.engine_fallback_reason = engine_fallback_reason;
    result.engine_fallback_from = engine_fallback_from;
    result.engine_fallback_to = engine_fallback_to;
  };

  if (profile.algorithm_mode == AlgorithmMode::Auto &&
      fallback_used &&
      (reason == QStringLiteral("local_client_gm_option_unsupported") ||
       reason == QStringLiteral("strict_policy_blocked_compatibility_bypass") ||
       reason == QStringLiteral("gm_probe_runtime_incompatible"))) {
    const auto standard_probe = probeCandidate(profile, AlgorithmCandidate::Standard, selected_ssh);
    if (!standard_probe.compatible && standard_probe.algorithm_mismatch) {
      if (reason == QStringLiteral("strict_policy_blocked_compatibility_bypass")) {
        result.error = QStringLiteral(
            "SFTP 严格模式已阻断旧版 ecgm 主机签名适配。"
            "请在“安全”菜单切换到“国密旧版服务端适配（降低校验强度）”后重试。");
      } else if (reason == QStringLiteral("gm_probe_runtime_incompatible")) {
        result.error = QStringLiteral(
            "SFTP 失败：当前国密 SSH 引擎与目标主机的国密实现存在运行时兼容问题。"
            "已协商 ecgm/sm2/sm3/sm4，但在 KEX 阶段后出现 internal error。");
      } else {
        result.error = QStringLiteral(
            "SFTP 失败：当前客户端不支持国密算法且服务端为纯国密模式，无法回退常规算法。");
      }
      populateResultContext();
      return result;
    }
  }

  if (profile.algorithm_mode == AlgorithmMode::GmOnly) {
    auto gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    if (!gm_probe.compatible &&
        SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(gm_probe.stderr_text) &&
        tryEngineFallback(gm_probe.stderr_text)) {
      gm_probe = probeCandidate(profile, AlgorithmCandidate::Gm, selected_ssh);
    }
    if (!gm_probe.compatible && stderrIndicatesStrictPolicyBlocked(gm_probe.stderr_text)) {
      result.error = QStringLiteral(
          "SFTP gm_only 失败：严格模式已阻断旧版 ecgm 主机签名适配。"
          "请切换到“国密旧版服务端适配（降低校验强度）”后重试。");
      populateResultContext();
      return result;
    }
    if (!gm_probe.compatible &&
        SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(gm_probe.stderr_text)) {
      result.error = QStringLiteral(
          "SFTP gm_only 失败：当前国密 SSH 引擎与目标主机的国密实现存在运行时兼容问题。"
          "已协商 ecgm/sm2/sm3/sm4，但在 KEX 阶段后出现 internal error。");
      populateResultContext();
      return result;
    }
    if (!gm_probe.compatible && gm_probe.algorithm_mismatch) {
      if (SshCommandBuilder::stderrIndicatesLocalGmOptionUnsupported(gm_probe.stderr_text)) {
        result.error = QStringLiteral(
            "SFTP gm_only 失败：当前 SSH 引擎不支持国密算法参数，请先构建并使用国密 OpenSSH 引擎。");
      } else {
        result.error = QStringLiteral("SFTP gm_only 失败：远端未接受国密算法。");
      }
      populateResultContext();
      return result;
    }
  }

  populateResultContext();

  if (audit_logger_ != nullptr && engine_fallback_used) {
    audit_logger_->logEvent(
        QStringLiteral("sftp_engine_fallback"),
        QJsonObject{{QStringLiteral("profile"), profile.name},
                    {QStringLiteral("reason"), engine_fallback_reason},
                    {QStringLiteral("from"), engine_fallback_from},
                    {QStringLiteral("to"), engine_fallback_to}});
  }

  if (!executableAvailable(selected_sftp)) {
    result.error = QStringLiteral("SFTP 引擎不可执行或不存在：%1").arg(selected_sftp);
    return result;
  }

  if (!executableAvailable(selected_ssh)) {
    result.error = QStringLiteral("SFTP 依赖的 SSH 引擎不可执行或不存在：%1").arg(selected_ssh);
    return result;
  }

  if (profile.auth_method == AuthMethod::Password && secrets.password.isEmpty()) {
    result.error = QStringLiteral("SFTP 密码为空：请重新连接该会话并输入登录密码后再试。");
    return result;
  }

  const auto ask_pass = prepareAskPass(secrets);

  QProcess process;
  process.setProgram(selected_sftp);
  process.setArguments(SshCommandBuilder::buildSftpArgs(
      profile,
      known_hosts_path_,
      candidate,
      selected_ssh,
      identity.identity_file,
      identity.certificate_file,
      sftpControlPath(profile, selected_ssh, candidate, gm_host_signature_policy_),
      QString()));
  process.setProcessEnvironment(ask_pass.environment);

  process.start();
  if (!process.waitForStarted(6000)) {
    result.error =
        QStringLiteral("failed to start sftp process: %1").arg(process.errorString());
  } else {
    for (const auto& command : commands) {
      process.write(command.toUtf8());
      process.write("\n");
    }
    process.write("quit\n");
    process.closeWriteChannel();

    if (!process.waitForFinished(timeout_ms)) {
      result.timed_out = true;
      process.kill();
      process.waitForFinished(2000);
      result.error = QStringLiteral("SFTP 执行超时（%1 秒）").arg(timeout_ms / 1000);
    }
    result.exit_code = process.exitCode();
    result.std_out = QString::fromUtf8(process.readAllStandardOutput());
    result.std_err = QString::fromUtf8(process.readAllStandardError());
    result.ok = !result.timed_out && result.exit_code == 0;
    if (result.ok &&
        sftpOutputIndicatesCommandFailure(
            QStringLiteral("%1\n%2").arg(result.std_out, result.std_err))) {
      result.ok = false;
      result.error = QStringLiteral("SFTP 命令执行失败，请查看上方输出。");
    }
    if (gm_host_signature_policy_ == GmHostSignaturePolicy::Strict &&
        stderrSuggestsCompatibility(result.std_err)) {
      result.ok = false;
      result.error = QStringLiteral(
          "SFTP 严格模式已阻断旧版国密适配。请切换到“国密旧版服务端适配（降低校验强度）”后重试。");
    }
  }

  for (const auto& path : identity.cleanup_files) {
    QFile::remove(path);
  }
  for (const auto& path : ask_pass.cleanup_files) {
    QFile::remove(path);
  }

  return result;
}

}  // namespace gmssh
