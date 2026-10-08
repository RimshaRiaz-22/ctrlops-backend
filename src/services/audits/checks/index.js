import { sshHardeningChecks } from './ssh-hardening/index.js';
import { applicationSecurityChecks } from './application-security/index.js';
import { fileSystemChecks } from './file-system/index.js';
import { firewallNetworkChecks } from './firewall-network/index.js';
import { userAccountChecks } from './user-account/index.js';
import { kernelSysctlChecks } from './kernel-sysctl/index.js';
import { updatesPatchingChecks } from './updates-patching/index.js';
import {
  webConfigurationChecks,
  webContentExposureChecks,
  webIdentificationChecks,
  webTlsChecks,
  webAccessControlChecks,
  webLoggingChecks,
} from './web/index.js';
import {
  dockerDaemonSocketChecks,
  dockerContainerHardeningChecks,
  dockerImageVulnsChecks,
  dockerNetworkChecks,
  dockerRuntimePolicyChecks,
  dockerSecretsChecks,
} from './docker/index.js';
import {
  dbAuthenticationChecks,
  dbConfigurationChecks,
  dbCredentialStorageChecks,
  dbNetworkExposureChecks,
  dbPrivilegesChecks,
  dbEncryptionChecks,
} from './database/index.js';

const byAudit = new Map([
  ['ssh-hardening', sshHardeningChecks],
  ['application-security', applicationSecurityChecks],
  ['file-system', fileSystemChecks],
  ['firewall-network', firewallNetworkChecks],
  ['user-account', userAccountChecks],
  ['kernel-sysctl', kernelSysctlChecks],
  ['updates-patching', updatesPatchingChecks],
  ['web-configuration', webConfigurationChecks],
  ['web-content-exposure', webContentExposureChecks],
  ['web-identification', webIdentificationChecks],
  ['web-tls', webTlsChecks],
  ['web-access-control', webAccessControlChecks],
  ['web-logging', webLoggingChecks],
  ['docker-container-hardening', dockerContainerHardeningChecks],
  ['docker-daemon-socket', dockerDaemonSocketChecks],
  ['docker-image-vulns', dockerImageVulnsChecks],
  ['docker-network', dockerNetworkChecks],
  ['docker-runtime-policy', dockerRuntimePolicyChecks],
  ['docker-secrets', dockerSecretsChecks],
  ['db-authentication', dbAuthenticationChecks],
  ['db-configuration', dbConfigurationChecks],
  ['db-credential-storage', dbCredentialStorageChecks],
  ['db-network-exposure', dbNetworkExposureChecks],
  ['db-privileges', dbPrivilegesChecks],
  ['db-encryption', dbEncryptionChecks],
]);

export function getChecksForAudit(auditId) {
  return byAudit.get(auditId) ?? null;
}

export function implementedAuditIds() {
  return new Set(byAudit.keys());
}

export function registerAuditChecks(auditId, checks) {
  byAudit.set(auditId, checks);
}

export function listServerAuditIds() {
  return [...byAudit.keys()].filter((id) =>
    [
      'ssh-hardening',
      'application-security',
      'file-system',
      'firewall-network',
      'user-account',
      'kernel-sysctl',
      'updates-patching',
    ].includes(id),
  );
}
