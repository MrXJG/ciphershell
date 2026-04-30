#include "core/ssh_command_builder.h"

#include <QRegularExpression>

namespace gmssh {
namespace {

QString target(const ConnectionProfile& profile) {
  return QStringLiteral("%1@%2").arg(profile.username, profile.host);
}

QStringList gmOptions() {
  return {
      QStringLiteral("-o"), QStringLiteral("KexAlgorithms=ecgm-sm2-sm3,sm2-sm3"),
      QStringLiteral("-o"), QStringLiteral("HostKeyAlgorithms=sm2,sm2-cert"),
      QStringLiteral("-o"), QStringLiteral("PubkeyAcceptedAlgorithms=sm2,sm2-cert"),
      QStringLiteral("-o"), QStringLiteral("Ciphers=sm4-ctr"),
      QStringLiteral("-o"), QStringLiteral("MACs=hmac-sm3"),
  };
}

QString encodeLocalOrRemoteRule(const ForwardRule& rule) {
  if (rule.target_port_or_path.trimmed().isEmpty()) {
    return QStringLiteral("%1:%2").arg(
        rule.bind_port_or_path,
        rule.target_addr);
  }

  return QStringLiteral("%1:%2:%3").arg(
      rule.bind_port_or_path,
      rule.target_addr,
      rule.target_port_or_path);
}

}  // namespace

QStringList SshCommandBuilder::buildCommonArgs(
    const ConnectionProfile& profile,
    const QString& known_hosts_file) {
  QStringList args = {
      QStringLiteral("-p"), QString::number(profile.port),
      QStringLiteral("-o"), QStringLiteral("ServerAliveInterval=30"),
      QStringLiteral("-o"), QStringLiteral("ServerAliveCountMax=3"),
      QStringLiteral("-o"), QStringLiteral("StrictHostKeyChecking=accept-new"),
      QStringLiteral("-o"),
      QStringLiteral("UserKnownHostsFile=%1").arg(known_hosts_file),
  };

  if (!profile.jump_host.trimmed().isEmpty()) {
    args << QStringLiteral("-J") << profile.jump_host.trimmed();
  }

  return args;
}

QStringList SshCommandBuilder::buildAlgorithmArgs(AlgorithmCandidate candidate) {
  if (candidate == AlgorithmCandidate::Gm) {
    return gmOptions();
  }
  return {};
}

QStringList SshCommandBuilder::buildForwardingArgs(const QList<ForwardRule>& rules) {
  QStringList args;
  for (const auto& rule : rules) {
    switch (rule.type) {
      case ForwardType::Local:
        args << QStringLiteral("-L") << encodeLocalOrRemoteRule(rule);
        break;
      case ForwardType::Remote:
        args << QStringLiteral("-R") << encodeLocalOrRemoteRule(rule);
        break;
      case ForwardType::DynamicSocks:
        args << QStringLiteral("-D") << rule.bind_port_or_path;
        break;
      case ForwardType::UnixSocket:
        args << QStringLiteral("-L") <<
            QStringLiteral("%1:%2").arg(rule.bind_port_or_path, rule.target_addr);
        break;
    }
  }
  return args;
}

QStringList SshCommandBuilder::buildAuthArgs(
    const ConnectionProfile& profile,
    const QString& identity_file,
    const QString& certificate_file) {
  QStringList args;

  if (!identity_file.trimmed().isEmpty()) {
    args << QStringLiteral("-i") << identity_file;
  }

  if (!certificate_file.trimmed().isEmpty()) {
    args << QStringLiteral("-o") <<
        QStringLiteral("CertificateFile=%1").arg(certificate_file);
  }

  if (profile.auth_method == AuthMethod::Password) {
    args << QStringLiteral("-o") << QStringLiteral("PreferredAuthentications=password");
  }

  return args;
}

QStringList SshCommandBuilder::buildProbeArgs(
    const ConnectionProfile& profile,
    const QString& known_hosts_file,
    AlgorithmCandidate candidate) {
  QStringList args = buildCommonArgs(profile, known_hosts_file);
  args << buildAlgorithmArgs(candidate);
  args << QStringLiteral("-o") << QStringLiteral("BatchMode=yes");
  args << QStringLiteral("-o") << QStringLiteral("PreferredAuthentications=none");
  args << QStringLiteral("-o") << QStringLiteral("NumberOfPasswordPrompts=0");
  args << QStringLiteral("-o") << QStringLiteral("ConnectTimeout=8");
  args << target(profile);
  args << QStringLiteral("exit");
  return args;
}

QStringList SshCommandBuilder::buildSessionArgs(
    const ConnectionProfile& profile,
    const QString& known_hosts_file,
    AlgorithmCandidate candidate,
    const QString& identity_file,
    const QString& certificate_file) {
  QStringList args = buildCommonArgs(profile, known_hosts_file);
  args << buildAlgorithmArgs(candidate);
  args << buildForwardingArgs(profile.forwarding_rules);
  args << buildAuthArgs(profile, identity_file, certificate_file);
  // GUI terminal is PTY-backed; keep forcing remote PTY allocation for interactive shells.
  args << QStringLiteral("-tt");
  args << target(profile);
  return args;
}

QStringList SshCommandBuilder::buildSftpArgs(
    const ConnectionProfile& profile,
    const QString& known_hosts_file,
    AlgorithmCandidate candidate,
    const QString& ssh_program,
    const QString& identity_file,
    const QString& certificate_file,
    const QString& control_path,
    const QString& batch_file) {
  QStringList args = {
      QStringLiteral("-P"), QString::number(profile.port),
      QStringLiteral("-o"), QStringLiteral("ConnectTimeout=10"),
      QStringLiteral("-o"), QStringLiteral("ServerAliveInterval=30"),
      QStringLiteral("-o"), QStringLiteral("ServerAliveCountMax=2"),
      QStringLiteral("-o"), QStringLiteral("StrictHostKeyChecking=accept-new"),
      QStringLiteral("-o"),
      QStringLiteral("UserKnownHostsFile=%1").arg(known_hosts_file),
  };

  if (!batch_file.trimmed().isEmpty()) {
    args << QStringLiteral("-b") << batch_file;
  } else {
    args << QStringLiteral("-o") << QStringLiteral("BatchMode=no");
  }

  if (!ssh_program.trimmed().isEmpty()) {
    args << QStringLiteral("-S") << ssh_program.trimmed();
  }

  if (!control_path.trimmed().isEmpty()) {
    args << QStringLiteral("-o") << QStringLiteral("ControlMaster=auto");
    args << QStringLiteral("-o") << QStringLiteral("ControlPersist=300");
    args << QStringLiteral("-o") << QStringLiteral("ControlPath=%1").arg(control_path.trimmed());
  }

  if (!profile.jump_host.trimmed().isEmpty()) {
    args << QStringLiteral("-J") << profile.jump_host.trimmed();
  }

  args << buildAlgorithmArgs(candidate);
  args << buildAuthArgs(profile, identity_file, certificate_file);
  args << target(profile);
  return args;
}

bool SshCommandBuilder::stderrIndicatesAlgorithmMismatch(const QString& stderr_text) {
  static const QStringList kPatterns = {
      QStringLiteral("Unable to negotiate"),
      QStringLiteral("no matching key exchange method found"),
      QStringLiteral("no matching host key type found"),
      QStringLiteral("no matching cipher found"),
      QStringLiteral("no matching MAC found"),
      QStringLiteral("Bad SSH2 KexAlgorithms"),
      QStringLiteral("Bad key types"),
      QStringLiteral("Unsupported KEX algorithm"),
      QStringLiteral("Bad SSH2 cipher spec"),
      QStringLiteral("Bad SSH2 MAC spec"),
  };

  for (const auto& pattern : kPatterns) {
    if (stderr_text.contains(pattern, Qt::CaseInsensitive)) {
      return true;
    }
  }

  return false;
}

bool SshCommandBuilder::stderrIndicatesLocalGmOptionUnsupported(const QString& stderr_text) {
  static const QStringList kPatterns = {
      QStringLiteral("Bad SSH2 KexAlgorithms"),
      QStringLiteral("Unsupported KEX algorithm"),
      QStringLiteral("Bad key types"),
      QStringLiteral("Bad SSH2 cipher spec"),
      QStringLiteral("Bad SSH2 MAC spec"),
  };

  for (const auto& pattern : kPatterns) {
    if (stderr_text.contains(pattern, Qt::CaseInsensitive)) {
      return true;
    }
  }

  return false;
}

bool SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(const QString& stderr_text) {
  static const QStringList kPatterns = {
      QStringLiteral("ssh_dispatch_run_fatal"),
      QStringLiteral("unexpected internal error"),
      QStringLiteral("message authentication code incorrect"),
      QStringLiteral("verify KEX signature"),
  };

  for (const auto& pattern : kPatterns) {
    if (stderr_text.contains(pattern, Qt::CaseInsensitive)) {
      return true;
    }
  }

  return false;
}

bool SshCommandBuilder::stderrIndicatesMacIncorrect(const QString& stderr_text) {
  return stderr_text.contains(
      QStringLiteral("message authentication code incorrect"),
      Qt::CaseInsensitive);
}

bool SshCommandBuilder::stderrIndicatesVerifyKexInternalError(const QString& stderr_text) {
  return stderr_text.contains(QStringLiteral("verify KEX signature"), Qt::CaseInsensitive) &&
         stderr_text.contains(QStringLiteral("unexpected internal error"), Qt::CaseInsensitive);
}

}  // namespace gmssh
