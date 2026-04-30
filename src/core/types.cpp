#include "core/types.h"

#include <QJsonArray>

namespace gmssh {
namespace {

template <typename T>
std::optional<T> fromStringMap(
    const QString& value,
    const QList<QPair<QString, T>>& entries) {
  for (const auto& entry : entries) {
    if (entry.first == value) {
      return entry.second;
    }
  }
  return std::nullopt;
}

template <typename T>
QString toStringMap(T value, const QList<QPair<QString, T>>& entries) {
  for (const auto& entry : entries) {
    if (entry.second == value) {
      return entry.first;
    }
  }
  return QStringLiteral("unknown");
}

}  // namespace

QString toString(AuthMethod method) {
  static const QList<QPair<QString, AuthMethod>> kEntries = {
      {QStringLiteral("password"), AuthMethod::Password},
      {QStringLiteral("sm2_key"), AuthMethod::Sm2Key},
      {QStringLiteral("openssh_cert"), AuthMethod::OpenSshCert},
      {QStringLiteral("x509_sm2_cert"), AuthMethod::X509Sm2Cert},
  };
  return toStringMap(method, kEntries);
}

std::optional<AuthMethod> authMethodFromString(const QString& value) {
  static const QList<QPair<QString, AuthMethod>> kEntries = {
      {QStringLiteral("password"), AuthMethod::Password},
      {QStringLiteral("sm2_key"), AuthMethod::Sm2Key},
      {QStringLiteral("openssh_cert"), AuthMethod::OpenSshCert},
      {QStringLiteral("x509_sm2_cert"), AuthMethod::X509Sm2Cert},
  };
  return fromStringMap(value, kEntries);
}

QString toString(AlgorithmMode mode) {
  static const QList<QPair<QString, AlgorithmMode>> kEntries = {
      {QStringLiteral("auto"), AlgorithmMode::Auto},
      {QStringLiteral("gm_only"), AlgorithmMode::GmOnly},
      {QStringLiteral("standard_only"), AlgorithmMode::StandardOnly},
  };
  return toStringMap(mode, kEntries);
}

std::optional<AlgorithmMode> algorithmModeFromString(const QString& value) {
  static const QList<QPair<QString, AlgorithmMode>> kEntries = {
      {QStringLiteral("auto"), AlgorithmMode::Auto},
      {QStringLiteral("gm_only"), AlgorithmMode::GmOnly},
      {QStringLiteral("standard_only"), AlgorithmMode::StandardOnly},
  };
  return fromStringMap(value, kEntries);
}

QString toString(ForwardType type) {
  static const QList<QPair<QString, ForwardType>> kEntries = {
      {QStringLiteral("local"), ForwardType::Local},
      {QStringLiteral("remote"), ForwardType::Remote},
      {QStringLiteral("dynamic_socks"), ForwardType::DynamicSocks},
      {QStringLiteral("unix_socket"), ForwardType::UnixSocket},
  };
  return toStringMap(type, kEntries);
}

std::optional<ForwardType> forwardTypeFromString(const QString& value) {
  static const QList<QPair<QString, ForwardType>> kEntries = {
      {QStringLiteral("local"), ForwardType::Local},
      {QStringLiteral("remote"), ForwardType::Remote},
      {QStringLiteral("dynamic_socks"), ForwardType::DynamicSocks},
      {QStringLiteral("unix_socket"), ForwardType::UnixSocket},
  };
  return fromStringMap(value, kEntries);
}

QString toString(AuditLevel level) {
  static const QList<QPair<QString, AuditLevel>> kEntries = {
      {QStringLiteral("minimal"), AuditLevel::Minimal},
      {QStringLiteral("normal"), AuditLevel::Normal},
      {QStringLiteral("verbose"), AuditLevel::Verbose},
  };
  return toStringMap(level, kEntries);
}

std::optional<AuditLevel> auditLevelFromString(const QString& value) {
  static const QList<QPair<QString, AuditLevel>> kEntries = {
      {QStringLiteral("minimal"), AuditLevel::Minimal},
      {QStringLiteral("normal"), AuditLevel::Normal},
      {QStringLiteral("verbose"), AuditLevel::Verbose},
  };
  return fromStringMap(value, kEntries);
}

QJsonObject toJson(const ForwardRule& rule) {
  QJsonObject object;
  object.insert(QStringLiteral("type"), toString(rule.type));
  object.insert(QStringLiteral("bind_addr"), rule.bind_addr);
  object.insert(QStringLiteral("bind_port_or_path"), rule.bind_port_or_path);
  object.insert(QStringLiteral("target_addr"), rule.target_addr);
  object.insert(
      QStringLiteral("target_port_or_path"),
      rule.target_port_or_path);
  return object;
}

std::optional<ForwardRule> forwardRuleFromJson(const QJsonObject& object) {
  if (!object.contains(QStringLiteral("type"))) {
    return std::nullopt;
  }

  const auto type =
      forwardTypeFromString(object.value(QStringLiteral("type")).toString());
  if (!type.has_value()) {
    return std::nullopt;
  }

  ForwardRule rule;
  rule.type = type.value();
  rule.bind_addr = object.value(QStringLiteral("bind_addr")).toString();
  rule.bind_port_or_path =
      object.value(QStringLiteral("bind_port_or_path")).toString();
  rule.target_addr = object.value(QStringLiteral("target_addr")).toString();
  rule.target_port_or_path =
      object.value(QStringLiteral("target_port_or_path")).toString();
  return rule;
}

QJsonObject toJson(const ConnectionProfile& profile) {
  QJsonObject object;
  object.insert(QStringLiteral("name"), profile.name);
  object.insert(QStringLiteral("host"), profile.host);
  object.insert(QStringLiteral("port"), profile.port);
  object.insert(QStringLiteral("username"), profile.username);
  object.insert(QStringLiteral("auth_method"), toString(profile.auth_method));
  object.insert(QStringLiteral("key_path"), profile.key_path);
  object.insert(QStringLiteral("cert_path"), profile.cert_path);
  object.insert(QStringLiteral("pfx_path"), profile.pfx_path);
  object.insert(QStringLiteral("jump_host"), profile.jump_host);
  object.insert(
      QStringLiteral("algorithm_mode"),
      toString(profile.algorithm_mode));
  object.insert(QStringLiteral("sftp_root"), profile.sftp_root);
  object.insert(QStringLiteral("save_credential"), profile.save_credential);
  object.insert(QStringLiteral("audit_level"), toString(profile.audit_level));

  QJsonArray forwarding_array;
  for (const auto& rule : profile.forwarding_rules) {
    forwarding_array.append(toJson(rule));
  }
  object.insert(QStringLiteral("forwarding_rules"), forwarding_array);

  return object;
}

std::optional<ConnectionProfile> connectionProfileFromJson(
    const QJsonObject& object,
    QString* error) {
  ConnectionProfile profile;
  profile.name = object.value(QStringLiteral("name")).toString();
  profile.host = object.value(QStringLiteral("host")).toString();
  profile.port = object.value(QStringLiteral("port")).toInt(22);
  profile.username = object.value(QStringLiteral("username")).toString();

  const auto auth_method =
      authMethodFromString(object.value(QStringLiteral("auth_method")).toString());
  if (!auth_method.has_value()) {
    if (error != nullptr) {
      *error = QStringLiteral("invalid auth_method");
    }
    return std::nullopt;
  }
  profile.auth_method = auth_method.value();

  profile.key_path = object.value(QStringLiteral("key_path")).toString();
  profile.cert_path = object.value(QStringLiteral("cert_path")).toString();
  profile.pfx_path = object.value(QStringLiteral("pfx_path")).toString();
  profile.jump_host = object.value(QStringLiteral("jump_host")).toString();

  const auto algorithm_mode = algorithmModeFromString(
      object.value(QStringLiteral("algorithm_mode")).toString(QStringLiteral("auto")));
  if (!algorithm_mode.has_value()) {
    if (error != nullptr) {
      *error = QStringLiteral("invalid algorithm_mode");
    }
    return std::nullopt;
  }
  profile.algorithm_mode = algorithm_mode.value();

  profile.sftp_root = object.value(QStringLiteral("sftp_root")).toString();
  profile.save_credential =
      object.value(QStringLiteral("save_credential")).toBool(false);

  const auto audit_level = auditLevelFromString(
      object.value(QStringLiteral("audit_level")).toString(QStringLiteral("normal")));
  if (!audit_level.has_value()) {
    if (error != nullptr) {
      *error = QStringLiteral("invalid audit_level");
    }
    return std::nullopt;
  }
  profile.audit_level = audit_level.value();

  const auto forwarding_array =
      object.value(QStringLiteral("forwarding_rules")).toArray();
  for (const auto& item : forwarding_array) {
    const auto rule = forwardRuleFromJson(item.toObject());
    if (!rule.has_value()) {
      if (error != nullptr) {
        *error = QStringLiteral("invalid forwarding rule");
      }
      return std::nullopt;
    }
    profile.forwarding_rules.push_back(rule.value());
  }

  if (profile.name.trimmed().isEmpty() || profile.host.trimmed().isEmpty() ||
      profile.username.trimmed().isEmpty()) {
    if (error != nullptr) {
      *error = QStringLiteral("name/host/username is required");
    }
    return std::nullopt;
  }

  return profile;
}

}  // namespace gmssh
