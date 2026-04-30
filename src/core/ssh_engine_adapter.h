#pragma once

#include "core/audit_logger.h"
#include "core/ssh_command_builder.h"
#include "core/types.h"

#include <QString>
#include <QHash>

namespace gmssh {

struct SftpExecutionResult {
  bool ok = false;
  int exit_code = -1;
  bool timed_out = false;
  QString std_out;
  QString std_err;
  QString error;
  QString ssh_program;
  QString sftp_program;
  AlgorithmMode selected_mode = AlgorithmMode::Auto;
  bool fallback_used = false;
  QString fallback_reason;
  bool engine_fallback_used = false;
  QString engine_fallback_reason;
  QString engine_fallback_from;
  QString engine_fallback_to;
};

enum class GmHostSignaturePolicy {
  Strict,
  CompatibilityBypass,
};

class SshEngineAdapter {
 public:
  explicit SshEngineAdapter(AuditLogger* audit_logger = nullptr);

  void setSshBinaryPath(QString path);
  void setSftpBinaryPath(QString path);
  void setLegacySshBinaryPath(QString path);
  void setLegacySftpBinaryPath(QString path);
  void setKnownHostsPath(QString path);

  const QString& sshBinaryPath() const;
  const QString& sftpBinaryPath() const;
  const QString& legacySshBinaryPath() const;
  const QString& legacySftpBinaryPath() const;

  void setGmHostSignaturePolicy(GmHostSignaturePolicy policy);
  GmHostSignaturePolicy gmHostSignaturePolicy() const;

  SshLaunchPlan prepareLaunch(
      const ConnectionProfile& profile,
      const SessionSecrets& secrets) const;

  SftpExecutionResult runSftpBatch(
      const ConnectionProfile& profile,
      const SessionSecrets& secrets,
      const QStringList& commands,
      int timeout_ms = 90000) const;

 private:
  struct EnginePreference {
    QString ssh;
    QString sftp;
  };

  struct ProbeOutcome {
    bool compatible = false;
    bool algorithm_mismatch = false;
    bool transport_reachable = false;
    QString stderr_text;
    int exit_code = -1;
  };

  struct IdentityMaterial {
    bool ok = true;
    QString error;
    QString identity_file;
    QString certificate_file;
    QStringList cleanup_files;
  };

  struct AskPassMaterial {
    QStringList cleanup_files;
    QProcessEnvironment environment;
  };

  AlgorithmCandidate chooseAlgorithmCandidate(
      const ConnectionProfile& profile,
      QString* reason,
      bool* fallback_used,
      const QString& ssh_program = {}) const;

  ProbeOutcome probeCandidate(
      const ConnectionProfile& profile,
      AlgorithmCandidate candidate,
      const QString& ssh_program = {}) const;

  bool clearHostKeyEntries(const ConnectionProfile& profile) const;

  IdentityMaterial prepareIdentityMaterial(
      const ConnectionProfile& profile,
      const SessionSecrets& secrets) const;

  AskPassMaterial prepareAskPass(const SessionSecrets& secrets) const;
  QProcessEnvironment runtimeEnvironment() const;

  static QString resolveBinary(const QString& candidate_path, const QString& fallback_name);

  QString ssh_binary_path_;
  QString sftp_binary_path_;
  QString legacy_ssh_binary_path_;
  QString legacy_sftp_binary_path_;
  QString known_hosts_path_;
  AuditLogger* audit_logger_ = nullptr;
  GmHostSignaturePolicy gm_host_signature_policy_ = GmHostSignaturePolicy::Strict;
  mutable QHash<QString, EnginePreference> engine_preference_cache_;
};

}  // namespace gmssh
