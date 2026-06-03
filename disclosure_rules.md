Defend behavior rules (kernel-level prevention, BPF-LSM where supported)
----------------------------------------------------------------------

These rules are evaluated inside the Defend agent and enforce in prevent mode. 
Source: github.com/elastic/protections-artifacts/behavior/rules/linux.

#### Potential Linux Tunneling and/or Port Forwarding
_Severity: n/a · Language: n/a_

This rule monitors for a set of Linux utilities that can be used for tunneling and port forwarding. Attackers can leverage tunneling and port forwarding techniques to bypass network defenses, establish hidden communication channels, and gain unauthorized access to internal resources, facilitating data exfiltration, lateral movement, and remote control.

```
process where event.type == "start" and event.action == "exec" and (
  (
    // Tunneling and/or Port Forwarding via process command line
    (
      process.command_line regex """.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}.*"""
    ) or
    // gost
    (
      process.name == "gost" and process.args like~ ("-L*", "-C*", "-R*")
    ) or
    // ngrok
    (
      process.name == "ngrok" and process.args in ("http", "https", "tcp", "tls") and
      not (process.executable like "/scratch/project/*/tools/ngrok/ngrok" and process.command_line like "*127.0.0.1*")
    ) or
    // earthworm
    (
      process.args == "-s" and process.args == "-d" and process.args == "rssocks"
    ) or
    // chisel
    (
      process.name like~ "chisel*" and process.args in ("client", "server")
    ) or
    // vscode
    (
      process.name == "code" and process.args == "tunnel" and
      not (
        process.args == "kill" or
        (process.executable like "/scratch/user/*/.vscode/code" and process.args == "-cli-data-dir")
      )
    ) or
    // QEMU
    (
      process.name like ("qemu-system-*", ".qemu-system-*") and
      process.args == "-netdev" and process.args like "*socket*" and (
        (
          process.args == "-nographic" and process.command_line like~ "*connect=*" and process.command_line like~ "*restrict=o
... [query truncated]
```

#### Manual Memory Password Searching Activity
_Severity: n/a · Language: n/a_

This rule detects the use of the 'strings' command to search for passwords in memory. Attackers may leverage this technique to extract sensitive information from memory. This behavior should not happen by default, and should be investigated thoroughly.

```
process where event.type == "start" and event.action == "exec" and process.name == "strings" and process.args == "/dev/mem"
```

#### Potential Linux Credential Dumping via Proc Filesystem
_Severity: n/a · Language: n/a_

Identifies the execution of the mimipenguin exploit script which is linux adaptation of Windows tool mimikatz. Mimipenguin exploit script is used to dump clear text passwords from a currently logged-in user. The tool exploits a known vulnerability CVE-2018-20781. Malicious actors can exploit the cleartext credentials in memory by dumping the process and extracting lines that have a high probability of containing cleartext passwords.

```
sequence by process.parent.executable, user.id with maxspan=60s
  [process where event.type == "start" and event.action == "exec" and process.name == "ps" and process.args : ("-eo", "pid", "command")]
  [process where event.type == "start" and event.action == "exec" and process.name in ("strings", "x86_64-linux-gnu-strings") and process.args : "/tmp/*"]
```

#### Potential Linux Credential Dumping via Unshadow
_Severity: n/a · Language: n/a_

Identifies the execution of the unshadow utility which is part of John the Ripper, a password-cracking tool on the host machine. Malicious actors can use the utility to retrieve the combined contents of the '/etc/shadow' and '/etc/password' files. Using the combined file generated from the utility, the malicious threat actors can use them as input for password-cracking utilities or prepare themselves for future operations by gathering credential information of the victim.

```
process where event.type == "start" and event.action == "exec" and
process.name == "unshadow" and process.args_count >= 2
```

#### Attempt to Clear Logs via Journalctl
_Severity: n/a · Language: n/a_

This rule monitors for attempts to clear logs using the "journalctl" command on Linux systems. Adversaries may use this technique to cover their tracks by deleting or truncating log files, making it harder for defenders to investigate their activities. The rule looks for the execution of "journalctl" with arguments that indicate log clearing actions, such as "--vacuum-time", "--vacuum-size", or "--vacuum-files".

```
process where event.type == "start" and event.action == "exec" and process.name == "journalctl" and
process.args like~ ("--vacuum-time=?s", "--vacuum-size=?M", "--vacuum-files=*") and
not (
  process.parent.args in ("/usr/lib/armbian/armbian-truncate-logs", "/root/innovasive_reverseproxy/backupscript/cleanup_hour.sh") or
  process.parent.executable == "/tmp/newroot/usr/bin/sudo"
)
```

#### Clearing of Shell History via Environment Variables
_Severity: n/a · Language: n/a_

This rule detects the clearing of the shell history via environment variables. Attackers may clear the shell history to hide their activities from being tracked. By leveraging environment variables such as HISTSIZE, HISTFILESIZE, HISTCONTROL, and HISTFILE, attackers can clear the shell history by setting them to 0, ignoring spaces, or redirecting the history to /dev/null, effectively erasing the command history.

```
process where event.type == "start" and event.action == "exec" and process.env_vars like~ (
  "HISTSIZE=0", "HISTFILESIZE=0", "HISTCONTROL=ignorespace", "HISTFILE=/dev/null"
)
```

#### Deletion of Shell History File
_Severity: n/a · Language: n/a_

Detects the deletion of shell history files through suspicious or commonly available tooling via a file deletion event. Shell history files are used to store the command history of a user. Adversaries may attempt to delete these files to remove evidence of their activity.

```
file where event.type == "deletion" and file.name in (
  ".bash_history", ".zsh_history", ".sh_history", ".ksh_history",
  ".history", ".csh_history", ".tcsh_history", "fish_history", ".ash_history"
) and
/* Enforce non-backup home & root directories to prevent false positives */
(
  file.path like ("/home/*/*", "/root/*", "/etc/*") and
  not file.path like ("/home/*/*/*", "/root/*/*")
) and
(
  process.name in (
    "rm", "sudo", "truncate", "unlink", "find", "xargs", "install", "shred", "vi", "vim",
    "vim.basic", "coreutils", "tar", "gzip", "bzip2", "rmdir", "mv", "cp", "ln", "busybox",
    "bash", "zsh", "sh", "tcsh", "csh", "ksh", "fish"
  ) or
  process.name like ".*" or
  process.executable like (
    "./*", "/dev/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/boot/*", "/sys/*",
    "/lost+found/*", "/proc/*", "/var/mail/*", "/var/www/*", "/root/*", "/home/*"
  )
)
```

#### In-Memory Process Execution
_Severity: n/a · Language: n/a_

This rule detects when a process is executed from a memory file descriptor (memfd). Attackers may use memfd to create and execute code directly in memory, bypassing traditional file-based detection mechanisms. The use of memfd for process execution is uncommon and may indicate an attempt to evade security controls.

```
process where event.type == "start" and event.action == "exec" and process.executable like "?memfd:*"
```

#### Potential Nologin SSH Backdoor
_Severity: n/a · Language: n/a_

This rule identifies instances where the `nologin` command is executed by the `sshd` process. This behavior is unusual and may indicate an attempt to manipulate a system user for backdoor access.

```
process where event.type == "start" and event.action == "exec" and process.name == "nologin " and
process.parent.name == "sshd"
```

#### Potential Proxy Execution via Sed
_Severity: n/a · Language: n/a_

This rule detects the execution of a command or binary through the Sed binary. Attackers may use this technique to execute commands while attempting to evade detection.

```
sequence with maxspan=3s
  [process where event.type == "start" and event.action == "exec" and process.parent.name == "sed" and
   process.parent.args == "-n" and not process.args like "s/*"] by process.entity_id
  [process where event.type == "start" and event.action == "exec" and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   process.parent.args == "-c"] by process.parent.entity_id
```

#### Linux Reverse Shell
_Severity: n/a · Language: n/a_

Detects the creation of a reverse shell through a suspicious parent child relationship spawned via a shell with suspicious command line arguments. Attackers may spawn reverse shells to establish persistence onto a target system.

```
sequence with maxspan=5s
  [network where event.type == "start" and event.action in ("connection_attempted", "connection_accepted") and 
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and 
   not (destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
     )
   )] by process.entity_id
  [process where event.type == "start" and event.action in ("exec", "fork") and 
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
     (process.args in ("-i", "-il", "-li")) or (process.parent.name == "socat" and process.parent.command_line like~ "*exec*")
   )] by process.parent.entity_id
```

#### Linux Reverse Shell via Child
_Severity: n/a · Language: n/a_

Detects the creation of a reverse shell through a shell with suspicious command line arguments. Attackers may spawn reverse shells to establish persistence onto a target system.

```
sequence by process.entity_id with maxspan=5s
  [network where event.type == "start" and event.action in ("connection_attempted", "connection_accepted") and 
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and destination.ip != null and 
   not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")]
  [process where event.type == "start" and event.action == "exec" and 
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
     process.args in ("-i", "-il", "-li") or
     (process.parent.name == "socat" and process.parent.command_line like~ "*exec*")
   )
  ]
```

#### Linux Reverse Shell via netcat
_Severity: n/a · Language: n/a_

Detects the creation of a reverse shell through netcat. Attackers may spawn reverse shells to establish persistence onto a target system.

```
sequence by process.entity_id with maxspan=5s
  [process where event.type == "start" and event.action == "exec" and 
   process.name in ("nc", "ncat", "netcat", "netcat.openbsd", "netcat.traditional", "nc.openbsd", "nc.traditional") and process.args_count >= 3 and 
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-e" and
   not process.args like~ ("-*z*", "-*l*")]
  [network where event.type == "start" and event.action in ("connection_attempted", "connection_accepted") and 
   process.name in ("nc", "ncat", "netcat", "netcat.openbsd", "netcat.traditional", "nc.openbsd", "nc.traditional") and 
   not (destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
     )
    )]
```

#### Non-interactive Shell Upgrade
_Severity: n/a · Language: n/a_

Identifies when a non-interactive terminal (tty) is being upgraded to a fully interactive shell. Attackers may upgrade a simple reverse shell to a fully interactive tty after obtaining initial access to a host, in order to obtain a more stable connection.

```
process where event.type == "start" and event.action == "exec" and (
  (
    process.name == "stty" and
    process.args == "raw" and
    process.args == "-echo" and
    process.args_count >= 3
  ) or
  (
    process.name == "script" and
    process.args in ("-qc", "-c") and
    process.args == "/dev/null" and
    process.args_count == 4
  )
) and
not (
  process.parent.command_line like ("linode-longview", "*bootstrap*", "*homebrew*", "*/home/*/.claude/shell-snapshots/snapshot*") or
  process.parent.executable in ("/usr/bin/expect", "/usr/bin/nsh-single-command", "/usr/bin/runc") or
  process.command_line == "stty -echo raw min 0 time 2" or
  process.args like ("/dev/tty*", "/dev/serial/*") or
  process.parent.args == "/usr/share/emacs/site-lisp/emacspeak/servers/dtk-exp"
)
```

#### Potential Reverse Shell Activity via TCP/UDP Socket
_Severity: n/a · Language: n/a_

This rule detects the execution of a shell process with suspicious arguments which may be indicative of reverse shell activity. Attackers may use the "/dev/tcp" or "/dev/udp" file descriptors to establish a reverse shell connection.

```
process where event.type == "start" and event.action == "exec" and process.parent.executable != null and (
  process.name in (
    "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "zmodload", "setsid", "nohup", "busybox",
    "timeout", "chroot", "logger", "printf"
  ) or
  process.name like ".*" or
  process.executable like (
    "/tmp/*", "/var/tmp/*", "/dev/shm/*", "/run/*", "/var/run/*", "/boot/*", "/home/*", "/root/*",
    "/opt/*", "/var/www/*", "/app/*", "/srv/*"
  )
) and
process.command_line like ("*/dev/tcp/*", "*/dev/udp/*", "*zsh/net/tcp*", "*zsh/net/udp*") and
process.command_line like ("*&>*", "*<>*", "*>&*", "*<&*") and
not (
  process.command_line like ("*/dev/tcp/127.0.0.1/*", "*/dev/tcp/localhost/*", "*/home/*/.claude/shell-snapshots/snapshot*", "*teleport-installer*") or
  process.parent.command_line like ("/usr/bin/runc init", "*/home/*/.claude/shell-snapshots/snapshot*", "runc init") or
  process.parent.args in ("/usr/bin/testssl.sh", "/usr/local/bin/testssl.sh", "/usr/bin/crun") or
  process.parent.executable like (
    "/usr/share/windsurf/resources/app/extensions/windsurf/bin/language_server_linux_x64", "/home/*/.cursor-server/bin/*/node", "/root/.cursor-server/cli/servers/*/server/node",
    "/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex/codex", "/opt/teleport/system/bin/t
... [query truncated]
```

#### Suspicious PHP Command Execution
_Severity: n/a · Language: n/a_

This rule monitors for suspicious PHP command executions by detecting the start of a PHP process with a command line argument that contains keywords commonly used by attackers to execute malicious code. These command line arguments include operations to execute code, create subprocesses, and encode or decode data.

```
process where event.type == "start" and event.action == "exec" and process.parent.executable != null and
process.executable like ("/bin/php*", "/usr/bin/php*", "/usr/local/bin/php*") and
process.args == "-r" and process.command_line like~ (
  "*exec(*", "*system(*", "*shell_exec(*", "*passthru(*", "*proc_open(*", "*pcntl_exec(*", "*popen(*", 
  "*eval(*", "*assert(*", "*create_function(*", "*preg_replace(*e*", "*include(*", "*require(*",
  "*base64_decode(*", "*gzinflate(*", "*gzuncompress(*", "*str_rot13(*", "*urldecode(*", "*chr(*", 
  "*ord(*", "*strrev(*", "*strtr(*", "*pack(*", "*unpack(*", "*curl_exec(*", "*curl_multi_exec(*",
  "*file_get_contents(*", "*fopen(*", "*fsockopen(*", "*pfsockopen(*", "*stream_socket_client(*",
  "*socket_create(*", "*socket_connect(*", "*socket_write(*", "*socket_read(*", "*mail(*",
  "*move_uploaded_file(*"
) and not (
  // Exclude web server processes as these are covered by other rules
  process.working_directory like (
    "/var/www/*", "/builds/*", "/home/*/jenkins/*", "/home/*/public_html*", "/var/lib/ldap-account-manager/config"
  ) or
  process.parent.args like ("/var/www/html/*", "source /home/*/.claude/shell*") or
  process.args like "/usr/local/cpanel/*" or
  process.command_line like (
    "*https://composer.github.io/installer.sig*",
    "*json_decode(file_get_contents('php://stdin')*"
  ) or
  process.parent.command_line == "run
... [query truncated]
```

#### General Privilege Escalation Sequence Detected
_Severity: n/a · Language: n/a_

This rule detects the execution of a binary, followed by a UID change event to 0 (root), and then the execution of a command that is used to check the current user's privileges. This sequence is often used by exploits to escalate privileges to root, and check if the escalation was successful.

```
sequence with maxspan=10s
  [process where event.type == "start" and event.action == "exec" and user.id != 0 and
   process.executable like ("/tmp/*", "/dev/shm/*", "/var/tmp/*", "/root/*", "/home/*", "./*", "/boot/*") and
   not process.parent.executable in ("/usr/bin/sw-engine", "/usr/sbin/sshd", "/usr/sbin/sw-engine-fpm", "/usr/lib/systemd/systemd")] by process.entity_id
  [process where event.type == "change" and event.action == "uid_change" and user.id == 0] by process.entity_id
  [process where event.type == "start" and event.action == "exec" and process.name in ("whoami", "id", "logname") and user.id == 0] by process.parent.entity_id
```

#### Potential Privilege Escalation via SUID Binary
_Severity: n/a · Language: n/a_

Identifies instances where a process is executed with user/group ID 0 (root), and a real user/group ID that is not 0. This is indicative of a process that has been granted SUID/SGID permissions, allowing it to run with elevated privileges. Attackers may leverage a misconfiguration for exploitation in order to escalate their privileges to root, or establish a backdoor for persistence.

```
process where event.type == "start" and event.action == "exec" and (
  (process.user.id == 0 and process.real_user.id != 0) or
  (process.group.id == 0 and process.real_group.id != 0)
) and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
  process.name in (
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell",
    "atobm", "base32", "base64", "basenc", "basez", "bc", "bridge", "busctl",
    "busybox", "bzip2", "cabal", "capsh", "choom", "chroot", "clamscan", "cmp",
    "column", "comm", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter",
    "dd", "debugfs", "dialog", "diff", "dig", "distcc",
    "dosbox", "ed", "efax", "elvish", "emacs", "eqn", "espeak", "expand", "expect",
    "fish", "fmt", "fold", "gcore", "gdb", "genie", "genisoimage", "gimp",
    "gtester", "hd", "hexdump", "highlight", "hping3", "iconv", "install",
    "ionice", "ispell", "jjs", "join", "jrunscript", "julia", "ksshell",
    "ld.so", "less", "links", "logsave", "look", "lua", "make",
    "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime",
    "nasm", "ncftp", "nft", "nl", "nm", "nmap", "nohup", "ntpdate",
    "od", "openssl", "openvpn", "pandoc", "paste", "perf", "pexec", "pg", "pidstat",
    "pr", "ptx", "python", "rc", "readelf", "restic", "rlwrap", "rsync", "rtorrent
... [query truncated]
```

#### Potential Privilege Escalation via SUID/SGID Proxy Execution
_Severity: n/a · Language: n/a_

Detects potential privilege escalation via SUID/SGID proxy execution on Linux systems. Attackers may exploit binaries with the SUID/SGID bit set to execute commands with elevated privileges. This rule identifies instances where a process is executed with root privileges (user ID 0 or group ID 0) while the real user or group ID is non-root, indicating potential misuse of SUID/SGID binaries.

```
process where event.type == "start" and event.action == "exec" and
startswith~(process.command_line, process.executable) and process.parent.args_count == 1 and
(
  (process.user.id == 0 and process.real_user.id != 0) or
  (process.group.id == 0 and process.real_group.id != 0)
) and
process.args in (
  "/bin/su", "/usr/bin/su",
  "/bin/umount", "/usr/bin/umount",
  "/bin/chfn", "/usr/bin/chfn",
  "/bin/chsh", "/usr/bin/chsh",
  "/bin/gpasswd", "/usr/bin/gpasswd",
  "/bin/newgrp", "/usr/bin/newgrp",
  "/usr/bin/newuidmap", "/usr/bin/newgidmap",
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/libexec/dbus-daemon-launch-helper",
  "/usr/lib/openssh/ssh-keysign", "/usr/libexec/openssh/ssh-keysign",
  "/usr/bin/pkexec", "/usr/libexec/pkexec", "/usr/lib/polkit-1/pkexec",
  "/usr/lib/snapd/snap-confine"
) and
process.args_count <= 2
/*
Need to exclude this in the future.
Leaving this in now because of the current CopyFail CVE-2026-24061, but it does not detect what this rule is supposed to detect.
and not process.name == "su" and process.args == "-"
*/
```

#### Privilege Escalation via PKEXEC Exploitation
_Severity: n/a · Language: n/a_

Identifies attempt to exploit a local privilege escalation in polkit pkexec (CVE-2021-4034) via unsecure environment variable injection. Successful exploitation allows an unprivileged user to escalate to the root user.

```
file where event.action != "deletion" and
process.executable like ("/tmp/*", "/dev/shm/*", "/var/tmp/*", "/root/*", "/home/*", "./*", "/boot/*") and
file.path like~ "/*GCONV_PATH*"
```


SIEM detection rules (run by the detection engine on ingested events)
----------------------------------------------------------------------

These rules run on a ~1-minute cadence against logs-endpoint.events.* and write to .alerts-security. 
Source: github.com/elastic/detection-rules/rules/linux.

#### Sensitive Files Compression
_Severity: medium · Language: kuery_

Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials and system configurations.

MITRE: Credential Access / T1552 Unsecured Credentials (T1552.001 Credentials In Files); Collection / T1005 Data from Local System; Collection / T1560 Archive Collected Data (T1560.001 Archive via Utility)

```
event.category:process and host.os.type:linux and event.type:start and
event.action:("exec" or "exec_event" or "start" or "executed" or "process_started") and
process.name:(zip or tar or gzip or hdiutil or 7z) and
process.args:
    (
      /root/.ssh/id_rsa or
      /root/.ssh/id_rsa.pub or
      /root/.ssh/id_ed25519 or
      /root/.ssh/id_ed25519.pub or
      /root/.ssh/authorized_keys or
      /root/.ssh/authorized_keys2 or
      /root/.ssh/known_hosts or
      /root/.bash_history or
      /etc/hosts or
      /home/*/.ssh/id_rsa or
      /home/*/.ssh/id_rsa.pub or
      /home/*/.ssh/id_ed25519 or
      /home/*/.ssh/id_ed25519.pub or
      /home/*/.ssh/authorized_keys or
      /home/*/.ssh/authorized_keys2 or
      /home/*/.ssh/known_hosts or
      /home/*/.bash_history or
      /root/.aws/credentials or
      /root/.aws/config or
      /home/*/.aws/credentials or
      /home/*/.aws/config or
      /home/*/.config/gcloud/credentials.db or
      /home/*/.config/gcloud/access_tokens.db or
      /home/*/.azure/credentials or
      /root/.azure/credentials or
      /root/.docker/config.json or
      /home/*/.docker/config.json or
      /root/.kube/config or
      /home/*/.kube/config or
      /etc/group or
      /etc/passwd or
      /etc/shadow or
      /etc/gshadow
    )
```

#### Potential External Linux SSH Brute Force Detected
_Severity: low · Language: eql_

Identifies multiple external consecutive login failures targeting a user account from the same source address within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to these accounts.

MITRE: Credential Access / T1110 Brute Force (T1110.001 Password Guessing, T1110.003 Password Spraying)

```
sequence by host.id, source.ip, user.name with maxspan=30s
  [ authentication where host.os.type == "linux" and 
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   not cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", 
       "::1", "FE80::/10", "FF00::/8") ] with runs = 60
```

#### Potential Successful SSH Brute Force Attack
_Severity: high · Language: eql_

Identifies multiple SSH login failures followed by a successful one from the same source address. Adversaries can attempt to login into multiple users with a common or known password to gain access to accounts.

MITRE: Credential Access / T1110 Brute Force (T1110.001 Password Guessing, T1110.003 Password Spraying); Initial Access / T1078 Valid Accounts

```
sequence by host.id, source.ip, user.name with maxspan=15s
  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "failure" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ] with runs=25
  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "success" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ]
```

#### System Log File Deletion
_Severity: medium · Language: eql_

Identifies the deletion of sensitive Linux system logs. This may indicate an attempt to evade detection or destroy forensic evidence on a system.

MITRE: Defense Evasion / T1070 Indicator Removal (T1070.002 Clear Linux or Mac System Logs, T1070.004 File Deletion)

```
file where host.os.type == "linux" and event.type == "deletion" and file.path in (
  "/var/run/utmp", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/faillog",
  "/var/log/syslog", "/var/log/messages", "/var/log/secure", "/var/log/auth.log", "/var/log/boot.log",
  "/var/log/kern.log", "/var/log/dmesg"
) and not (
  process.name in ("gzip", "executor", "dockerd") or
  (process.executable in ("/usr/bin/podman", "/dev/fd/3") and file.name == "lastlog")
)
```

#### Sudo Command Enumeration Detected
_Severity: low · Language: eql_

This rule monitors for the usage of the sudo -l command, which is used to list the allowed and forbidden commands for the invoking user. Attackers may execute this command to enumerate commands allowed to be executed with sudo permissions, potentially allowing to escalate privileges to root.

MITRE: Discovery / T1033 System Owner/User Discovery; Discovery / T1069 Permission Groups Discovery (T1069.001 Local Groups); Privilege Escalation / T1548 Abuse Elevation Control Mechanism (T1548.003 Sudo and Sudo Caching)

```
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.name == "sudo" and process.args == "-l" and
  process.args_count == 2 and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  not process.args == "dpkg"
```

#### SUID/SGUID Enumeration Detected
_Severity: medium · Language: eql_

This rule monitors for the usage of the "find" command in conjunction with SUID and SGUID permission arguments. SUID (Set User ID) and SGID (Set Group ID) are special permissions in Linux that allow a program to execute with the privileges of the file owner or group, respectively, rather than the privileges of the user running the program. In case an attacker is able to enumerate and find a binary that is misconfigured, they might be able to leverage this misconfiguration to escalate privileges by exploiting vulnerabilities or built-in features in the privileged program.

MITRE: Discovery / T1083 File and Directory Discovery; Privilege Escalation / T1548 Abuse Elevation Control Mechanism (T1548.001 Setuid and Setgid)

```
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "find" and process.args : "-perm" and process.args : (
  "/6000", "-6000", "/4000", "-4000", "/2000", "-2000", "/u=s", "-u=s", "/g=s", "-g=s", "/u=s,g=s", "/g=s,u=s"
) and not (
  user.Ext.real.id == "0" or group.Ext.real.id == "0" or process.args_count >= 12 or
  (process.args : "/usr/bin/pkexec" and process.args : "-xdev" and process.args_count == 7)
)
```

#### File Transfer or Listener Established via Netcat
_Severity: medium · Language: eql_

A netcat process is engaging in network activity on a Linux host. Netcat is often used as a persistence mechanism by exporting a reverse shell or by serving a shell on a listening port. Netcat is also sometimes used for data exfiltration.

MITRE: Execution / T1059 Command and Scripting Interpreter (T1059.004 Unix Shell); Command and Control / T1095 Non-Application Layer Protocol; Exfiltration / T1048 Exfiltration Over Alternative Protocol (T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol)

```
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") and
process.args like~ (
  /* bind shell to specific port or listener */
  "-*l*","-*p*",
  /* reverse shell to command-line interpreter used for command execution */
  "-*e*",
  /* file transfer via stdout/pipe */
  ">","<", "|"
)
```

#### Potential Webshell Deployed via Apache Struts CVE-2023-50164 Exploitation
_Severity: high · Language: eql_

Identifies successful exploitation of CVE-2023-50164, a critical path traversal vulnerability in Apache Struts 2 file upload functionality. This high-fidelity rule detects a specific attack sequence where a malicious multipart/form-data POST request with WebKitFormBoundary is made to a Struts .action upload endpoint, immediately followed by the creation of a JSP web shell file by a Java process in Tomcat's webapps directories. This correlated activity indicates active exploitation resulting in remote code execution capability through unauthorized file upload and web shell deployment.

MITRE: Initial Access / T1190 Exploit Public-Facing Application; Persistence / T1505 Server Software Component (T1505.003 Web Shell); Command and Control / T1105 Ingress Tool Transfer

```
sequence by agent.id with maxspan=10s
  [network where data_stream.dataset == "network_traffic.http" and
      http.request.method == "POST" and
      http.request.body.content like "*WebKitFormBoundary*" and
      url.path like~ "*upload*.action"]
  [file where data_stream.dataset == "endpoint.events.file" and
      host.os.type == "linux" and
      event.action == "creation" and
      process.name == "java" and
      file.extension == "jsp" and
      file.path like "*/webapps/*" and
      not file.path like "*/WEB-INF/*" and
      not file.path like "*/META-INF/*"
  ]
```

#### Successful SSH Authentication from Unusual IP Address
_Severity: low · Language: kuery_

This rule leverages the new_terms rule type to detect successful SSH authentications by an IP- address that has not been authenticated in the last 5 days. This behavior may indicate an attacker attempting to gain access to the system using a valid account.

MITRE: Initial Access / T1078 Valid Accounts; Lateral Movement / T1021 Remote Services (T1021.004 SSH)

```
event.category:authentication and host.os.type:linux and event.action:ssh_login and event.outcome:success
```

#### Cron Job Created or Modified
_Severity: medium · Language: eql_

This rule monitors for (ana)cron jobs being created or renamed. Linux cron jobs are scheduled tasks that can be leveraged by system administrators to set up scheduled tasks, but may be abused by malicious actors for persistence, privilege escalation and command execution. By creating or modifying cron job configurations, attackers can execute malicious commands or scripts at predefined intervals, ensuring their continued presence and enabling unauthorized activities.

MITRE: Persistence / T1053 Scheduled Task/Job (T1053.003 Cron); Privilege Escalation / T1053 Scheduled Task/Job (T1053.003 Cron); Execution / T1053 Scheduled Task/Job (T1053.003 Cron)

```
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path like (
  "/etc/cron.allow", "/etc/cron.deny", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*",
  "/etc/cron.monthly/*", "/etc/crontab", "/var/spool/cron/crontabs/*", "/var/spool/anacron/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd", "/opt/elasticbeanstalk/bin/platform-engine",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/opt/imunify360/venv/bin/python3",
    "/opt/eset/efs/lib/utild", "/usr/sbin/anacron", "/usr/bin/podman", "/kaniko/kaniko-
... [query truncated]
```

#### Suspicious Child Execution via Web Server
_Severity: medium · Language: eql_

Identifies suspicious child processes executed via a web server, which may suggest a vulnerability and remote shell access. Attackers may exploit a vulnerability in a web application to execute commands via a web server, or place a backdoor file that can be abused to gain code execution as a mechanism for persistence.

MITRE: Persistence / T1505 Server Software Component (T1505.003 Web Shell); Initial Access / T1190 Exploit Public-Facing Application; Execution / T1059 Command and Scripting Interpreter

```
process where host.os.type == "linux" and event.type == "start" and process.parent.executable != null and (
  process.parent.name like (
    "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm*", "mongrel_rails", "haproxy",
    "gunicorn", "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "uvicorn",
    "tornado", "hypercorn", "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel",
    "php-cgi", "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
  ) or
  user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
  user.id in ("33", "498", "48") or
  (process.name == "java" and ?process.working_directory like "/u0?/*")
) and (
  process.executable like (
    "/tmp/*", "/var/tmp/*", "/dev/shm/*", "./*", "/run/*", "/var/run/*", "/boot/*", "/sys/*", "/lost+found/*",
    "/proc/*", "/var/mail/*", "/var/www/*", "/home/*", "/root/*" 
  ) or
  process.name like~ (
    // Hidden processes
    ".*",
    // Suspicious file formats
    "*.elf", "*.sh", "*.py", "*.rb", "*.pl", "*.lua*", "*.php*", ".js",
    // Scheduled tasks
    "systemd", "cron", "crond",
    // Network utilities often used for reverse shells
    "nc", "netcat", "ncat", "telnet", "socat", "openssl", "nc.openbsd", "ngrok", "nc.traditional",
    // Cloud CLI
    "az", "gcloud", "aws",
    //
... [query truncated]
```

#### SSH Key Generated via ssh-keygen
_Severity: low · Language: eql_

This rule identifies the creation of SSH keys using the ssh-keygen tool, which is the standard utility for generating SSH keys. Users often create SSH keys for authentication with remote services. However, threat actors can exploit this tool to move laterally across a network or maintain persistence by generating unauthorized SSH keys, granting them SSH access to systems.

MITRE: Persistence / T1098 Account Manipulation (T1098.004 SSH Authorized Keys); Lateral Movement / T1021 Remote Services (T1021.004 SSH); Lateral Movement / T1563 Remote Service Session Hijacking (T1563.001 SSH Hijacking)

```
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.executable == "/usr/bin/ssh-keygen" and file.path : ("/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*") and
not file.name : "known_hosts.*"
```

#### Unusual Process Spawned from Web Server Parent
_Severity: low · Language: esql_

This rule detects unusual processes spawned from a web server parent process by identifying low frequency counts of process spawning activity. Unusual process spawning activity may indicate an attacker attempting to establish persistence, execute malicious commands, or establish command and control channels on the host system. ESQL rules have limited fields available in its alert documents. Make sure to review the original documents to aid in the investigation of this alert.

MITRE: Persistence / T1505 Server Software Component (T1505.003 Web Shell); Execution / T1059 Command and Scripting Interpreter (T1059.004 Unix Shell, T1059.006 Python, T1059.007 JavaScript, T1059.011 Lua); Command and Control / T1071 Application Layer Protocol; Initial Access / T1190 Exploit Public-Facing Application

```
from logs-endpoint.events.process-* metadata _id, _index, _version
| mv_expand event.action
| where
    host.os.type == "linux" and
    event.type == "start" and
    event.action == "exec" and (
      (
        process.parent.name in (
            "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "mongrel_rails", "gunicorn",
            "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "tornado", "hypercorn",
            "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel", "php-cgi",
            "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
        ) or
        process.parent.name like "php-fpm*" or
        user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
        user.id in ("33", "498", "48") or
        (process.parent.name == "java" and process.parent.working_directory like "/u0?/*") or
        process.parent.working_directory like "/var/www/*"
      )
    ) and (
        process.name in (
          "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat", "openssl", "busybox",
          "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "nohup", "setsid", "mkfifo", "mknod",
          "node", "socket"
        ) or
        process.name like "python*" or
        process.name like "php*" or
        process.name like "perl"
... [query truncated]
```

#### Potential Sudo Privilege Escalation via CVE-2019-14287
_Severity: high · Language: eql_

This rule monitors for the execution of a suspicious sudo command that is leveraged in CVE-2019-14287 to escalate privileges to root. Sudo does not verify the presence of the designated user ID and proceeds to execute using a user ID that can be chosen arbitrarily. By using the sudo privileges, the command "sudo -u#-1" translates to an ID of 0, representing the root user. This exploit may work for sudo versions prior to v1.28.

MITRE: Privilege Escalation / T1068 Exploitation for Privilege Escalation; Privilege Escalation / T1548 Abuse Elevation Control Mechanism (T1548.003 Sudo and Sudo Caching)

```
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.name == "sudo" and process.args == "-u#-1"
```
