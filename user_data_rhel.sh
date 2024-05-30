#!/bin/bash
sudo -i
set +e

##################################
# CIS Patch 3 v2.1 by Johit Kumar#
##################################

# Function to check if a mount option is set
check_mount_option() {
    local mount_point=$1
    local option=$2
    mount | grep -E "\s$mount_point\s" | grep -q "$option"
}

# Function to update /etc/fstab and remount with a given option
update_and_remount() {
    local mount_point=$1
    local option=$2
    if ! grep -E "\s$mount_point\s" /etc/fstab | grep -q "$option"; then
        if grep -E "\s$mount_point\s" /etc/fstab; then
            sed -i "/\s$mount_point\s/ s/defaults/defaults,$option/" /etc/fstab
        else
            echo "tmpfs $mount_point tmpfs defaults,$option 0 0" >> /etc/fstab
        fi
    fi
    mount -o remount,$option $mount_point
}

# Function to ensure a specific mount option is set
ensure_mount_option() {
    local mount_point=$1
    local option=$2
    if ! check_mount_option $mount_point $option; then
        update_and_remount $mount_point $option
    fi
}

# Function to disable core dump storage
disable_core_dumps() {
    echo "kernel.core_pattern=/dev/null" > /etc/sysctl.d/99-disable-core-dump.conf
    sysctl -p /etc/sysctl.d/99-disable-core-dump.conf
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "* soft core 0" >> /etc/security/limits.conf
    sysctl -w fs.suid_dumpable=0
    ulimit -c 0
}

# Function to check for unconfined services
check_unconfined_services() {
    if ! sestatus | grep -q "SELinux status:.*enabled"; then
        exit 1
    fi
    UNCONFINED_SERVICES=$(ps -eZ | egrep 'initrc|unconfined_u' | grep -vE 'tr|grep|ps -eZ')
    if [ ! -z "$UNCONFINED_SERVICES" ]; then
        semanage fcontext -a -t bin_t '/usr/bin/amazon-ssm-agent'
        restorecon -v '/usr/bin/amazon-ssm-agent'
        systemctl restart amazon-ssm-agent
    fi
}

# Function to ensure a single firewall configuration utility is in use
ensure_single_firewall() {
    local ACTIVE_FIREWALLS=0
    [ "$(systemctl is-active firewalld)" == "active" ] && ((ACTIVE_FIREWALLS++))
    [ "$(systemctl is-active iptables)" == "active" ] && ((ACTIVE_FIREWALLS++))
    [ "$(systemctl is-active ufw)" == "active" ] && ((ACTIVE_FIREWALLS++))
    if [ $ACTIVE_FIREWALLS -gt 1 ]; then
        exit 1
    elif [ $ACTIVE_FIREWALLS -eq 0 ]; then
        systemctl enable firewalld
        systemctl start firewalld
    fi
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --permanent --add-port=22/tcp
    firewall-cmd --reload
}

# Function to ensure nftables base chains exist
ensure_nftables_chains() {
    if ! command -v nft &> /dev/null; then
        exit 1
    fi
    local CHAINS=("input" "forward" "output")
    for CHAIN in "${CHAINS[@]}"; do
        if ! nft list chain ip filter $CHAIN &> /dev/null; then
            nft add chain ip filter $CHAIN { type filter hook $CHAIN priority 0 \; }
        fi
    done
}

# Function to ensure users must provide password for escalation
ensure_password_escalation() {
    local SUDOERS_FILE="/etc/sudoers"
    local tempfile=$(mktemp)
    cp $SUDOERS_FILE $tempfile
    grep -v 'NOPASSWD' $tempfile > $SUDOERS_FILE
    visudo -c -f $SUDOERS_FILE || cp $tempfile $SUDOERS_FILE
    rm -f $tempfile
}

# Function to configure PAM modules
configure_pam() {
    local PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    for pam_file in "${PAM_FILES[@]}"; do
        if ! grep -q "pam_pwhistory.so" "$pam_file"; then
            sed -i '/pam_unix.so/a password    required    pam_pwhistory.so use_authtok remember=5' "$pam_file"
        fi
    done
}

# Function to configure password policies
configure_password_policies() {
    echo "difok = 2" >> /etc/security/pwquality.conf
    echo "remember = 5" >> /etc/security/pwhistory.conf
    sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/" /etc/login.defs
    sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/" /etc/login.defs
    sed -i "s/^INACTIVE.*/INACTIVE 30/" /etc/login.defs
    for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
        chage --maxdays 365 "$user"
        chage --warndays 7 "$user"
        chage --inactive 30 "$user"
    done
}

# Function to configure audit rules
configure_audit_rules() {
    cat <<EOF > /etc/audit/rules.d/sudoers.rules
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

    cat <<EOF > /etc/audit/rules.d/setfacl.rules
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -k perm_mod
EOF

    cat <<EOF > /etc/audit/rules.d/chacl.rules
-a always,exit -F arch=b64 -S chacl -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chacl -F auid>=1000 -F auid!=unset -k perm_mod
EOF

    cat <<EOF > /etc/audit/rules.d/usermod.rules
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=unset -k usermod
-a always,exit -F arch=b32 -S execve -F path=/usr/sbin/usermod -F auid>=1000 -F auid!=unset -k usermod
EOF

    cat <<EOF > /etc/audit/rules.d/kernel_modules.rules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOF

    augenrules --load
}

# Ensure nosuid, nodev, noexec options set on /tmp and /dev/shm partitions
ensure_mount_option "/tmp" "nosuid"
ensure_mount_option "/tmp" "nodev"
ensure_mount_option "/tmp" "noexec"
ensure_mount_option "/dev/shm" "noexec"

# Disable core dumps
disable_core_dumps

# Check for unconfined services
check_unconfined_services

# Ensure a single firewall is in use
ensure_single_firewall

# Ensure nftables base chains exist
ensure_nftables_chains

# Ensure password for escalation
ensure_password_escalation

# Configure PAM modules
configure_pam

# Configure password policies
configure_password_policies

# Configure audit rules
configure_audit_rules

echo "Successfully Completed"
