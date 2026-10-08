-- Pin bastion identity separately from the target host (TOFU).
ALTER TABLE servers
  ADD COLUMN bastion_host_key_fingerprint VARCHAR(128),
  ADD COLUMN bastion_host_key_algorithm VARCHAR(64);
