#include "core/ssh_command_builder.h"
#include "core/ssh_engine_adapter.h"
#include "core/types.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonObject>
#include <QList>
#include <QTemporaryDir>
#include <cassert>

using namespace gmssh;

QString writeFakeSsh(QTemporaryDir& dir, const QString& name, const QByteArray& stderr_line) {
  auto file_name = name;
#if defined(Q_OS_WIN)
  file_name.append(QStringLiteral(".cmd"));
#endif
  const auto path = dir.filePath(file_name);
  QFile file(path);
  assert(file.open(QIODevice::WriteOnly | QIODevice::Text));
#if defined(Q_OS_WIN)
  file.write("@echo off\r\n");
  file.write("echo ");
  file.write(stderr_line);
  file.write(" 1>&2\r\n");
  file.write("exit /b 255\r\n");
#else
  file.write("#!/bin/sh\n");
  file.write("echo '");
  file.write(stderr_line);
  file.write("' >&2\n");
  file.write("exit 255\n");
#endif
  file.close();
  file.setPermissions(
      QFileDevice::ReadOwner |
      QFileDevice::WriteOwner |
      QFileDevice::ExeOwner |
      QFileDevice::ReadGroup |
      QFileDevice::ExeGroup |
      QFileDevice::ReadOther |
      QFileDevice::ExeOther);
  return path;
}

void test_profile_roundtrip() {
  ConnectionProfile input;
  input.name = "demo";
  input.host = "10.0.13.1";
  input.port = 22;
  input.username = "root";
  input.auth_method = AuthMethod::X509Sm2Cert;
  input.key_path = "/tmp/key.pem";
  input.cert_path = "/tmp/cert.pem";
  input.pfx_path = "/tmp/a.pfx";
  input.jump_host = "jump@10.0.13.10:22";
  input.algorithm_mode = AlgorithmMode::Auto;
  input.sftp_root = "/root";
  input.save_credential = true;
  input.audit_level = AuditLevel::Verbose;
  input.forwarding_rules = {
      ForwardRule{ForwardType::Local, "", "127.0.0.1:8080", "10.0.13.1", "80"},
      ForwardRule{ForwardType::DynamicSocks, "", "1080", "", ""},
  };

  const auto encoded = toJson(input);
  const auto decoded = connectionProfileFromJson(encoded, nullptr);
  assert(decoded.has_value());
  assert(decoded->name == input.name);
  assert(decoded->host == input.host);
  assert(decoded->algorithm_mode == input.algorithm_mode);
  assert(decoded->forwarding_rules.size() == 2);
}

void test_algorithm_builder() {
  ConnectionProfile profile;
  profile.name = "p";
  profile.host = "127.0.0.1";
  profile.username = "u";

  const auto gm = SshCommandBuilder::buildAlgorithmArgs(AlgorithmCandidate::Gm);
  const auto standard =
      SshCommandBuilder::buildAlgorithmArgs(AlgorithmCandidate::Standard);
  const auto sftp_args = SshCommandBuilder::buildSftpArgs(
      profile,
      QStringLiteral("/tmp/known_hosts"),
      AlgorithmCandidate::Gm,
      QStringLiteral("/tmp/gmssh-ssh"),
      QString(),
      QString(),
      QStringLiteral("/tmp/gmssh-control"),
      QStringLiteral("/tmp/batch"));
  const auto interactive_sftp_args = SshCommandBuilder::buildSftpArgs(
      profile,
      QStringLiteral("/tmp/known_hosts"),
      AlgorithmCandidate::Gm,
      QStringLiteral("/tmp/gmssh-ssh"),
      QString(),
      QString(),
      QStringLiteral("/tmp/gmssh-control"),
      QString());

  assert(!gm.isEmpty());
  assert(standard.isEmpty());
  assert(gm.contains(QStringLiteral("KexAlgorithms=ecgm-sm2-sm3,sm2-sm3")));
  assert(gm.contains(QStringLiteral("HostKeyAlgorithms=sm2,sm2-cert")));
  assert(gm.contains(QStringLiteral("PubkeyAcceptedAlgorithms=sm2,sm2-cert")));
  assert(gm.contains(QStringLiteral("Ciphers=sm4-ctr")));
  assert(gm.contains(QStringLiteral("MACs=hmac-sm3")));
  assert(sftp_args.contains(QStringLiteral("-S")));
  assert(sftp_args.contains(QStringLiteral("/tmp/gmssh-ssh")));
  assert(sftp_args.contains(QStringLiteral("ConnectTimeout=10")));
  assert(sftp_args.contains(QStringLiteral("ServerAliveInterval=30")));
  assert(sftp_args.contains(QStringLiteral("ServerAliveCountMax=2")));
  assert(sftp_args.contains(QStringLiteral("ControlMaster=auto")));
  assert(sftp_args.contains(QStringLiteral("ControlPersist=300")));
  assert(sftp_args.contains(QStringLiteral("ControlPath=/tmp/gmssh-control")));
  assert(sftp_args.contains(QStringLiteral("-b")));
  assert(!sftp_args.contains(QStringLiteral("BatchMode=no")));
  assert(!interactive_sftp_args.contains(QStringLiteral("-b")));
  assert(interactive_sftp_args.contains(QStringLiteral("BatchMode=no")));

  const auto mismatch = SshCommandBuilder::stderrIndicatesAlgorithmMismatch(
      "Unable to negotiate with 10.0.13.1: no matching key exchange method found");
  assert(mismatch);

  const auto local_client_mismatch = SshCommandBuilder::stderrIndicatesAlgorithmMismatch(
      "command-line line 0: Bad SSH2 KexAlgorithms 'sm2-sm3'.");
  assert(local_client_mismatch);

  const auto local_client_unsupported =
      SshCommandBuilder::stderrIndicatesLocalGmOptionUnsupported(
          "Unsupported KEX algorithm \"sm2-sm3\"");
  assert(local_client_unsupported);

  const auto gm_runtime_incompatible =
      SshCommandBuilder::stderrIndicatesGmRuntimeIncompatible(
          "ssh_dispatch_run_fatal: Connection to 10.0.13.1 port 22: unexpected internal error");
  assert(gm_runtime_incompatible);

  const auto mac_incorrect =
      SshCommandBuilder::stderrIndicatesMacIncorrect(
          "ssh_dispatch_run_fatal: Connection to 10.0.13.1 port 22: message authentication code incorrect");
  assert(mac_incorrect);

  const auto verify_kex_internal =
      SshCommandBuilder::stderrIndicatesVerifyKexInternalError(
          "input_kex_gen_reply: verify KEX signature: unexpected internal error");
  assert(verify_kex_internal);
}

void test_forwarding_builder() {
  QList<ForwardRule> rules;
  rules.push_back(ForwardRule{ForwardType::Local, "", "8080", "10.0.13.2", "80"});
  rules.push_back(ForwardRule{ForwardType::Remote, "", "9090", "127.0.0.1", "22"});
  rules.push_back(ForwardRule{ForwardType::DynamicSocks, "", "1080", "", ""});

  const auto args = SshCommandBuilder::buildForwardingArgs(rules);
  assert(args.contains("-L"));
  assert(args.contains("-R"));
  assert(args.contains("-D"));
}

void test_hostsig_policy_plumbing() {
  SshEngineAdapter adapter;
  adapter.setKnownHostsPath(QDir::temp().filePath("gmssh-test-known-hosts"));
  adapter.setLegacySshBinaryPath(QStringLiteral("/tmp/ssh-legacy"));
  adapter.setLegacySftpBinaryPath(QStringLiteral("/tmp/sftp-legacy"));
  assert(adapter.legacySshBinaryPath() == QStringLiteral("/tmp/ssh-legacy"));
  assert(adapter.legacySftpBinaryPath() == QStringLiteral("/tmp/sftp-legacy"));

  ConnectionProfile profile;
  profile.name = "policy";
  profile.host = "10.0.13.1";
  profile.port = 22;
  profile.username = "root";
  profile.auth_method = AuthMethod::Password;
  profile.algorithm_mode = AlgorithmMode::StandardOnly;

  SessionSecrets secrets;
  secrets.password = "dummy-password";

  adapter.setGmHostSignaturePolicy(GmHostSignaturePolicy::Strict);
  const auto strict_plan = adapter.prepareLaunch(profile, secrets);
  assert(strict_plan.ok);
  assert(!strict_plan.gm_hostsig_compatibility_bypass);
  assert(!strict_plan.engine_fallback_used);
  assert(
      strict_plan.environment.value(QStringLiteral("GMSSH_ECGM_HOSTSIG_BYPASS")) ==
      QStringLiteral("0"));

  adapter.setGmHostSignaturePolicy(GmHostSignaturePolicy::CompatibilityBypass);
  const auto compat_plan = adapter.prepareLaunch(profile, secrets);
  assert(compat_plan.ok);
  assert(compat_plan.gm_hostsig_compatibility_bypass);
  assert(
      compat_plan.environment.value(QStringLiteral("GMSSH_ECGM_HOSTSIG_BYPASS")) ==
      QStringLiteral("1"));
}

void test_engine_fallback_from_modern_kex_internal_error() {
  QTemporaryDir temp;
  assert(temp.isValid());

  const auto modern_ssh = writeFakeSsh(
      temp,
      QStringLiteral("ssh-modern"),
      QByteArrayLiteral(
          "input_kex_gen_reply: verify KEX signature: unexpected internal error"));
  const auto legacy_ssh = writeFakeSsh(
      temp,
      QStringLiteral("ssh-legacy-ecgm"),
      QByteArrayLiteral("Authentication failed."));

  SshEngineAdapter adapter;
  adapter.setKnownHostsPath(temp.filePath(QStringLiteral("known_hosts")));
  adapter.setSshBinaryPath(modern_ssh);
  adapter.setLegacySshBinaryPath(legacy_ssh);
  adapter.setLegacySftpBinaryPath(temp.filePath(QStringLiteral("sftp-legacy-ecgm")));

  ConnectionProfile profile;
  profile.name = "kylin-legacy";
  profile.host = "10.0.13.1";
  profile.port = 22;
  profile.username = "root";
  profile.auth_method = AuthMethod::Password;
  profile.algorithm_mode = AlgorithmMode::Auto;

  const auto plan = adapter.prepareLaunch(profile, SessionSecrets{});
  assert(plan.ok);
  assert(plan.program == legacy_ssh);
  assert(plan.selected_mode == AlgorithmMode::GmOnly);
  assert(plan.engine_fallback_used);
  assert(plan.engine_fallback_from == modern_ssh);
  assert(plan.engine_fallback_to == legacy_ssh);
  assert(
      plan.engine_fallback_reason ==
      QStringLiteral("gm_probe_verify_kex_internal_modern_to_legacy"));
  assert(!plan.fallback_used);
}

void test_known_hosts_repair_handles_sm2_lines() {
  QTemporaryDir temp;
  assert(temp.isValid());

  const auto known_hosts_path = temp.filePath(QStringLiteral("known_hosts"));
  QFile known_hosts(known_hosts_path);
  assert(known_hosts.open(QIODevice::WriteOnly | QIODevice::Text));
  known_hosts.write(
      "10.0.13.1 sm2 "
      "AAAAA3NtMgAAAANzbTIAAABBBFJFo5vt8NrQ7qMvzDioKde9IJ00OKeyMdD3s2jInm1HX6jEo3pHfNljTtgEqA3SaSKU+qEkH3wefm8Z+o3Rl9o=\n");
  known_hosts.write(
      "[10.0.13.2]:2222 sm2 "
      "AAAAA3NtMgAAAANzbTIAAABBBB7XRHt1w0sNElw94cdkK/oekLVIp9xMLd3LqPa9GIyhH34LAKI4bp4QEk6+HNmY/TISFrhMtDfgNFGyu0Cz0No=\n");
  known_hosts.write(
      "10.0.13.2 ssh-ed25519 "
      "AAAAC3NzaC1lZDI1NTE5AAAAIDyC+M/puTSGwbl2VncIrXn62MioexP/wc7n5KD6PJ/9\n");
  known_hosts.close();

  SshEngineAdapter adapter;
  adapter.setKnownHostsPath(known_hosts_path);

  ConnectionProfile profile;
  profile.host = QStringLiteral("10.0.13.2");
  profile.port = 2222;

  assert(adapter.clearHostKeyEntries(profile));

  QFile verify(known_hosts_path);
  assert(verify.open(QIODevice::ReadOnly | QIODevice::Text));
  const auto text = QString::fromUtf8(verify.readAll());
  verify.close();

  assert(!text.contains(QStringLiteral("[10.0.13.2]:2222")));
  assert(!text.contains(QStringLiteral("10.0.13.2 ssh-ed25519")));
  assert(text.contains(QStringLiteral("10.0.13.1 sm2")));
}

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  test_profile_roundtrip();
  test_algorithm_builder();
  test_forwarding_builder();
  test_hostsig_policy_plumbing();
  test_engine_fallback_from_modern_kex_internal_error();
  test_known_hosts_repair_handles_sm2_lines();
  return 0;
}
