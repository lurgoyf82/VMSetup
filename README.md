# Raffo Setup Helpers

Raffo Setup guides operators through first-boot provisioning tasks for Debian/Ubuntu based hosts. The launcher (`firstboot.sh`) now chains a series of focused helpers, each gated by `run_step` prompts from `raffolib.sh` so you can opt into the stages you need.

## Quick start (run from a fresh VM)

Run the following as root on Debian/Ubuntu to bootstrap Raffo Setup and start the guided flow:
```bash
	apt update -y && apt install -y git && 
	git clone -b main https://github.com/lurgoyf82/VMSetup.git /root/vmsetup && 
	chmod +x /root/vmsetup/firstboot.sh && 
	/root/vmsetup/firstboot.sh
```

1. **System Updates** (`setupupdates.sh`)
   - Refreshes package indexes.
   - Provides menu-driven upgrade options (standard upgrade, dist-upgrade, autoremove, clean).
   - Uses `ask_menu`, `ask_yesno`, and Raffo status banners so you know what is happening.

2. **Timezone & Locale** (`setuptimezone.sh`)
   - Detects the current timezone and lets you pick a region/city via whiptail menus.
   - Optionally sets the system locale after prompting for the desired value.

3. **User Accounts** (`setupusers.sh`)
   - Guides you through creating a new sudo-enabled operator account.
   - Copies existing `authorized_keys`, configures sudoers drop-ins (passwordless or timed), and can lock the root account.
   - Offers optional password policies via `chage` and PAM pwquality enforcement.

4. **Network Configuration** (`setupnetwork.sh`)
   - Maintains the previous helper behavior for editing interface addressing and DNS.

5. **SSH Hardening** (`setupssh.sh`)
   - Backs up `sshd_config`, then offers menu-driven changes for port, root login policy, and password authentication.
   - Installs authorized keys using `ask_input` and validates/reloads the SSH daemon after edits.
   
6. **Security Hardening** (`setuphardening.sh`)
   - Applies kernel network tunables (reverse path filtering, redirect suppression, SYN cookies) with backups.
   - Enforces AppArmor profiles, installs a tuned Fail2ban policy, and deploys console/SSH warning banners.
   - Offers IPv6 enable/disable toggles, reviews enabled services for disablement, and runs a Lynis audit with reports stored under `/var/log/raffosetup`.

7. **Firewall Configuration** (`setupfirewall.sh`)
   - Guides you through default policies and port exceptions for common firewall managers.

8. **Logging Configuration** (`setuplogging.sh`)
   - Switches `systemd-journald` to persistent storage and prompts for disk usage thresholds and rate limiting.
   - Optionally configures remote forwarding via `rsyslog` or `systemd-journal-upload`, then restarts affected services with a summary report.

9. **Guest Agent** (`setupguestagent.sh`)
   - Detects the hypervisor automatically via `systemd-detect-virt` and installs the matching tools (QEMU, VMware, Hyper-V, or VirtualBox).
   - Enables the guest agent services at boot and, on KVM/Proxmox, provisions a serial console in GRUB and systemd.

10. **Cleanup & Summary** (`setupcleanup.sh`)
   - Performs `apt-get autoremove --purge` and `apt-get clean`, purges leftover temporary files, and forces a log rotation.
   - Writes `/var/log/raffosetup/summary.txt` with hostname, IP addresses, firewall status, guest agent details, and pending reboot status.
   - Marks `/var/lib/raffosetup/.done` to indicate Raffo Setup completed successfully.

Each helper can be re-run independently by executing its script directly (e.g., `bash /root/setupssh.sh`).
