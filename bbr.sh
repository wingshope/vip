#!/bin/bash
# Edition : Stable Edition V3.0
# Auther  : Mbah Wings
# (C) Copyright 2023
# =========================================

red='\e[1;31m'
green='\e[0;32m'
purple='\e[0;35m'
orange='\e[0;33m'
NC='\e[0m'
clear
#if [[ -e /usr/local/sbin/bbr ]]; then
     echo ""
#     echo -e "${green}TCP BBR Already Install${NC}"
     echo ""
#	 read -n1 -r -p "Press any key to continue..."
#	 menu
#else

echo -e "Installing TCP BBR Mod By Wings VPN"
echo -e "Please Wait BBR Installation Will Starting . . ."
sleep 5
clear

touch /usr/local/sbin/bbr

Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		Add_To_New_Line "$1" "$2"
	fi
}

Install_BBR(){
echo -e "\e[32;1m================================\e[0m"
echo -e "\e[32;1mInstalling TCP BBR...\e[0m"
if [ -n "$(lsmod | grep bbr)" ];then
echo -e "\e[0;32mSuccesfully Installed TCP BBR.\e[0m"
echo -e "\e[32;1m================================\e[0m"
return 1
fi
echo -e "\e[0;32mStarting To Install BBR...\e[0m"
modprobe tcp_bbr
Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
sysctl -p
if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
	echo -e "\e[0;32mTCP BBR Install Success!\e[0m"
else
	echo -e "\e[1;31mFailed To Install BBR!\e[0m"
fi
echo -e "\e[32;1m================================\e[0m"
}

Optimize_Parameters(){
echo -e "\e[32;1m================================\e[0m"
echo -e "\e[32;1mOptimize Parameters...\e[0m"
modprobe ip_conntrack
Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
################################
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.route_localnet=1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_forward = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.forwarding = 1"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.forwarding = 1"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.disable_ipv6 = 0"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_ra = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_ra = 2"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget = 50000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget_usecs = 5000"
Check_And_Add_Line "/etc/sysctl.conf" "#fs.file-max = 51200"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.optmem_max = 65536"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 10000"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_all = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_broadcasts = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_ignore_bogus_error_responses = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.secure_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.secure_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.send_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.send_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.rp_filter = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.rp_filter = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_intvl = 15"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_probes = 5"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_synack_retries = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rfc1337 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_timestamps = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 15"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 1024 65535"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 2000000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_rmem_min = 8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_wmem_min = 8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 0"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_ignore = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_ignore = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_announce = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_announce = 2"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_autocorking = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_slow_start_after_idle = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 30000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_notsent_lowat = 16384"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_no_metrics_save = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn_fallback = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_frto = 0"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "vm.swappiness = 1"
Check_And_Add_Line "/etc/sysctl.conf" "vm.overcommit_memory = 1"
Check_And_Add_Line "/etc/sysctl.conf" "#vm.nr_hugepages=1280"
Check_And_Add_Line "/etc/sysctl.conf" "kernel.pid_max=64000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh3=8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh2=4096"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh1=2048"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh3=8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh2=4096"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh1=2048"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.netfilter.nf_conntrack_max = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.nf_conntrack_max = 262144"

##############################
##############################
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultTimeoutStopSec=30s"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitCORE=infinity"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitNOFILE=65535"
echo -e "\e[0;32mSuccesfully Optimize Parameters.\e[0m"
echo -e "\e[32;1m================================\e[0m"
}
Install_BBR
Optimize_Parameters
rm -f /root/bbr.sh >/dev/null 2>&1
echo -e '\e[32;1m============================================================\e[0m'
echo -e '\e[0;32m                  Installation Success!                     \e[0m'
echo -e '\e[32;1m============================================================\e[0m'
sleep 3
#fi
