#pragma once

#include <QJsonObject>
#include <QList>
#include <QProcessEnvironment>
#include <QString>
#include <QStringList>
#include <optional>

namespace gmssh {

enum class AuthMethod {
  Password,
  Sm2Key,
  OpenSshCert,
  X509Sm2Cert,
};

enum class AlgorithmMode {
  Auto,
  GmOnly,
  StandardOnly,
};

enum class ForwardType {
  Local,
  Remote,
  DynamicSocks,
  UnixSocket,
};

enum class AuditLevel {
  Minimal,
  Normal,
  Verbose,
};

struct ForwardRule {
  ForwardType type = ForwardType::Local;
  QString bind_addr;
  QString bind_port_or_path;
  QString target_addr;
  QString target_port_or_path;
};

struct ConnectionProfile {
  QString name;
  QString host;
  int port = 22;
  QString username;
  AuthMethod auth_method = AuthMethod::Password;
  QString key_path;
  QString cert_path;
  QString pfx_path;
  QString jump_host;
  AlgorithmMode algorithm_mode = AlgorithmMode::Auto;
  QList<ForwardRule> forwarding_rules;
  QString sftp_root;
  bool save_credential = false;
  AuditLevel audit_level = AuditLevel::Normal;
};

struct SessionSecrets {
  QString password;
  QString key_passphrase;
  QString pfx_password;
};

struct SshLaunchPlan {
  bool ok = false;
  QString error;
  QString program;
  QStringList arguments;
  QProcessEnvironment environment;
  QStringList cleanup_files;
  AlgorithmMode selected_mode = AlgorithmMode::Auto;
  bool fallback_used = false;
  QString fallback_reason;
  bool gm_hostsig_compatibility_bypass = false;
  bool engine_fallback_used = false;
  QString engine_fallback_reason;
  QString engine_fallback_from;
  QString engine_fallback_to;
};

QString toString(AuthMethod method);
std::optional<AuthMethod> authMethodFromString(const QString& value);

QString toString(AlgorithmMode mode);
std::optional<AlgorithmMode> algorithmModeFromString(const QString& value);

QString toString(ForwardType type);
std::optional<ForwardType> forwardTypeFromString(const QString& value);

QString toString(AuditLevel level);
std::optional<AuditLevel> auditLevelFromString(const QString& value);

QJsonObject toJson(const ForwardRule& rule);
std::optional<ForwardRule> forwardRuleFromJson(const QJsonObject& object);

QJsonObject toJson(const ConnectionProfile& profile);
std::optional<ConnectionProfile> connectionProfileFromJson(
    const QJsonObject& object,
    QString* error = nullptr);

}  // namespace gmssh
