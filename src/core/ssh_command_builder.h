#pragma once

#include "core/types.h"

#include <QString>
#include <QStringList>

namespace gmssh {

enum class AlgorithmCandidate {
  Gm,
  Standard,
};

class SshCommandBuilder {
 public:
  static QStringList buildCommonArgs(
      const ConnectionProfile& profile,
      const QString& known_hosts_file);

  static QStringList buildAlgorithmArgs(AlgorithmCandidate candidate);

  static QStringList buildForwardingArgs(const QList<ForwardRule>& rules);

  static QStringList buildAuthArgs(
      const ConnectionProfile& profile,
      const QString& identity_file,
      const QString& certificate_file);

  static QStringList buildProbeArgs(
      const ConnectionProfile& profile,
      const QString& known_hosts_file,
      AlgorithmCandidate candidate);

  static QStringList buildSessionArgs(
      const ConnectionProfile& profile,
      const QString& known_hosts_file,
      AlgorithmCandidate candidate,
      const QString& identity_file,
      const QString& certificate_file);

  static QStringList buildSftpArgs(
      const ConnectionProfile& profile,
      const QString& known_hosts_file,
      AlgorithmCandidate candidate,
      const QString& ssh_program,
      const QString& identity_file,
      const QString& certificate_file,
      const QString& control_path,
      const QString& batch_file);

  static bool stderrIndicatesAlgorithmMismatch(const QString& stderr_text);
  static bool stderrIndicatesLocalGmOptionUnsupported(const QString& stderr_text);
  static bool stderrIndicatesGmRuntimeIncompatible(const QString& stderr_text);
  static bool stderrIndicatesMacIncorrect(const QString& stderr_text);
  static bool stderrIndicatesVerifyKexInternalError(const QString& stderr_text);
};

}  // namespace gmssh
