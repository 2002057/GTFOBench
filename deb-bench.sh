#!/bin/bash
a="result.txt"
b="fail.txt"
c="manual.txt"
txtrst='\033[0m' # Color off
txtblu='\e[1;36m' # Blue bold
txtgrn='\e[1;32m' # Green bold
txtred='\e[1;31m' # Red bold


echo -e "\n==========================================================================================\n" >> $b
echo -e "Failed " >> $b
echo -e "\n==========================================================================================\n" >> $b

echo -e "\n==========================================================================================\n" >> $c
echo -e "Manual Check Required " >> $c
echo -e "\n==========================================================================================\n" >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.1 Ensure Only Necessary Authentication and Authorization Modules Are Enabled\n" >> $a
apache2ctl -M | egrep 'auth._' >> $a
apache2ctl -M | egrep 'ldap' >> $a

if [[ -n $(apache2ctl -M | egrep 'auth._') ]]; then
	if [[ -n $(apache2ctl -M | egrep 'ldap') ]]; then
		echo -e "${txtred}2.1 Fail${txtrst}"
		echo -e "2.1, " >> $b
	else	
		echo -e "${txtgrn}2.1 Pass${txtrst}"
	fi
else
	echo "2.1 Fail\n"
	echo -e "2.1, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.2 Ensure the Log Config Module Is Enabled\n" >> $a
apache2ctl -M | grep log_config >> $a
if [[ -n $(apache2ctl -M | grep log_config) ]]; then
	echo -e "${txtgrn}2.2 Pass${txtrst}"
else
	echo -e "${txtred}2.2 Fail${txtrst}"
	echo -e "2.2, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.3 Ensure the WebDAV Modules Are Disabled\n" >> $a
apache2ctl -M | grep ' dav_[[:print:]]+module' >> $a
if [[ -n $(apache2ctl -M | grep ' dav_[[:print:]]+module') ]]; then
	echo -e "${txtred}2.3 Fail${txtrst}"
	echo -e "2.3, " >> $b
else
	echo -e "${txtgrn}2.3 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.4 Ensure the Status Module Is Disabled\n" >> $a
apache2ctl -M | egrep 'status_module' >> $a
if [[ -n $(apache2ctl -M | egrep 'status_module') ]]; then
	echo -e "${txtred}2.4 Fail${txtrst}"
	echo -e "2.4, " >> $b
else
	echo -e "${txtgrn}2.4 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.5 Ensure the Autoindex Module Is Disabled\n" >> $a
apache2ctl -M | grep autoindex_module >> $a
if [[ -n $(apache2ctl -M | grep autoindex_module) ]]; then
	echo -e "${txtred}2.5 Fail${txtrst}"
	echo -e "2.5, " >> $b
else
	echo -e "${txtgrn}2.5 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.6 Ensure the Proxy Modules Are Disabled\n" >> $a
apache2ctl -M | grep proxy_ >> $a
if [[ -n $(apache2ctl -M | grep proxy_) ]]; then
	echo -e "${txtred}2.6 Fail${txtrst}"
	echo -e "2.6, " >> $b
else
	echo -e "${txtgrn}2.6 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.7 Ensure the User Directories Module Is Disabled\n" >> $a
apache2ctl -M | grep userdir_ >> $a
if [[ -n $(apache2ctl -M | grep userdir_) ]]; then
	echo -e "${txtred}2.7 Fail${txtrst}"
	echo -e "2.7, " >> $b
else
	echo -e "${txtgrn}2.7 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.8 Ensure the Info Module Is Disabled\n" >> $a
apache2ctl -M | egrep 'info_module' >> $a
if [[ -n $(apache2ctl -M | egrep 'info_module') ]]; then
	echo -e "${txtred}2.8 Fail${txtrst}"
	echo -e "2.8, " >> $b
else
	echo -e "${txtgrn}2.8 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n2.9 Ensure the Basic and Digest Authentication Modules are Disabled\n" >> $a
apache2ctl -M | grep auth_basic_module >> $a
apache2ctl -M | grep auth_digest_module >> $a
if [[ -n $(apache2ctl -M | grep auth_basic_module) ]]; then
	if [[ -n $(apache2ctl -M | grep auth_digest_module) ]]; then
		echo -e "${txtred}2.9 Fail${txtrst}"
		echo -e "2.9, " >> $b
	else	
		echo -e "${txtgrn}2.9 Pass${txtrst}"
	fi
else
	echo -e "${txtred}2.9 Fail\n${txtrst}"
	echo -e "2.9, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.1 Ensure the Apache Web Server Runs As a Non-Root User\n" >> $a

grep -i 'APACHE_RUN_USER' /etc/apache2/envvars | cut -d '=' -f2 >> $a
grep -i 'APACHE_RUN_GROUP' /etc/apache2/envvars | cut -d '=' -f2 >> $a
grep '^UID_MIN' /etc/login.defs >> $a
id www-data >> $a
ps axu | grep apache2 | grep -v '^root' >> $a
echo -e "3.1 Manual Check Required"
echo -e "3.1," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.2 Ensure the Apache User Account Has an Invalid Shell\n" >> $a
grep www-data /etc/passwd >> $a
echo -e "3.2 Manual Check Required"
echo -e "3.2," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.3 Ensure the Apache User Account Is Locked\n" >> $a
passwd -S www-data >> $a
echo -e "3.2 Manual Check Required"
echo -e "3.2," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.4 Ensure Apache Directories and Files Are Owned By Root\n" >> $a
find /etc/apache2/ \! -user root -ls >> $a
if [[ -n $(find /etc/apache2/ \! -user root -ls) ]]; then
	echo -e "${txtred}3.4 Fail${txtrst}"
	echo "3.4, " >> $b
else
	echo -e "${txtgrn}3.4 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.5 Ensure the Group Is Set Correctly on Apache Directories and Files\n" >> $a
find /etc/apache2/ -path /etc/apache2//htdocs -prune -o \!  -group root -ls >> $a
if [[ -n $(find /etc/apache2/ -path /etc/apache2//htdocs -prune -o \!  -group root -ls) ]]; then
	echo -e "${txtred}3.5 Fail${txtrst}"
	echo "3.5, " >> $b
else
	echo -e "${txtgrn}3.5 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.6 Ensure Other Write Access on Apache Directories and Files Is Restricted\n" >> $a
find -L /etc/apache2/ \! -type l -perm /o=w -ls >> $a
if [[ -n $(find -L /etc/apache2/ \! -type l -perm /o=w -ls) ]]; then
	echo -e "${txtred}3.6 Fail${txtrst}"
	echo "3.6, " >> $b
else
	echo -e "${txtgrn}3.6 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.7 Ensure the Core Dump Directory Is Secured\n" >> $a
echo -e "3.7 Manual Check Required"
echo -e "3.7," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.8 Ensure the Lock File Is Secured\n" >> $a
echo -e "3.8 Manual Check Required"
echo -e "3.8," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.9 Ensure the Pid File Is Secured\n" >> $a
echo -e "3.9 Manual Check Required"
echo -e "3.9," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.10 Ensure the ScoreBoard File Is Secured\n" >> $a
echo -e "3.10 Manual Check Required"
echo -e "3.10," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.11 Ensure Group Write Access for the Apache Directories and Files Is Properly Restricted\n" >> $a
find -L /etc/apache2/ \! -type l -perm /g=w -ls >> $a
if [[ -n $(find -L /etc/apache2/ \! -type l -perm /g=w -ls) ]]; then
	echo -e "${txtred}3.11 Fail${txtrst}"
	echo "3.11, " >> $b
else
	echo -e "${txtgrn}3.11 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.12 Ensure Group Write Access for the Document Root Directories and Files Is Properly Restricted\n" >> $a
GRP=$(grep 'APACHE_RUN_GROUP' /etc/apache2/envvars | cut -d'=' -f2)
DOCROOT=$(grep -i 'DocumentRoot' /etc/apache2/sites-available/000-default.conf | cut -d' ' -f2 | tr -d '\"')
find -L $DOCROOT -group $GRP -perm /g=w -ls >> $a

if [[ -n $(find -L $DOCROOT -group $GRP -perm /g=w -ls) ]]; then
	echo -e "${txtred}3.12 Fail${txtrst}"
	echo "3.12, " >> $b
else
	echo -e "${txtgrn}3.12 Pass${txtrst}"
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n3.13 Ensure Access to Special Purpose Application Writable Directories is Properly Restricted\n" >> $a
echo -e "3.13 Manual Check Required"
echo -e "3.13," >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n4.1 Ensure Access to OS Root Directory Is Denied By Default\n" >> $a
perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "Require all denied" >> $a
if [[ -n $(perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "Require all denied") ]]; then
	echo -e "${txtgrn}4.1 Pass${txtrst}"
else
	echo -e "${txtred}4.1 Fail${txtrst}"
	echo "4.1, " >> $b
fi



echo -e "\n==========================================================================================\n" >> $a
echo -e "\n4.2 Ensure Appropriate Access to Web Content Is Allowed\n" >> $a
echo -e "4.2 Manual Check Required"
echo -e "4.2," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n4.3 Ensure OverRide Is Disabled for the OS Root Directory\n" >> $a
perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "AllowOverride None" >> $a
perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "AllowOverrideList" >> $a
if [[ -n $(perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "AllowOverride None") ]]; then
	if [[ -n $(perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "AllowOverrideList") ]]; then
		echo -e "${txtgrn}4.3 Pass${txtrst}"
	else
		echo -e "${txtred}4.3 Fail${txtrst}"
		echo "4.3, " >> $b
	fi
else
	echo -e "${txtred}4.3 Fail${txtrst}"
	echo "4.3, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n4.4 Ensure OverRide Is Disabled for All Directories\n" >> $a
grep -i AllowOverride /etc/apache2/apache2.conf >> $a
grep -i AllowOverrideList /etc/apache2/apache2.conf >> $a
echo -e "4.4 Manual Check Required"
echo -e "4.4," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.1 Ensure Options for the OS Root Directory Are Restricted\n" >> $a
perl -ne 'print if /^ *<Directory */i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "Options None" >> $a
if [[ -n $(perl -ne 'print if /^ *<Directory */i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "Options None") ]]; then
	echo -e "${txtgrn}5.1 Pass${txtrst}"
else
	echo -e "${txtred}5.1 Fail${txtrst}"
	echo "5.1, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.2 Ensure Options for the Web Root Directory Are Restricted\n" >> $a
perl -ne 'print if /^ *<Directory */i .. /<\/Directory/i' /etc/apache2/apache2.conf | grep "Options" >> $a
echo -e "5.2 Manual Check Required"
echo -e "5.2," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.3 Ensure Options for Other Directories Are Minimized\n" >> $a
grep -i -A 12 '<Directory[[:space:]]' /etc/apache2/apache2.conf | grep "Options" >> $a
echo -e "5.3 Manual Check Required"
echo -e "5.3," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.4 Ensure Default HTML Content Is Removed\n" >> $a
echo -e "5.4 Manual Check Required"
echo -e "5.4," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.5 Ensure the Default CGI Content printenv Script Is Removed\n" >> $a
echo -e "5.5 Manual Check Required"
echo -e "5.5," >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.6 Ensure the Default CGI Content test-cgi Script Is Removed\n" >> $a
echo -e "\nManual Check Required\n" >> $a
echo -e "5.6 Manual Check Required"
echo -e "5.6," >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.7 Ensure HTTP Request Methods Are Restricted\n" >> $a
cat /etc/apache2/apache2.conf  | grep "LimitExcept" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf  | grep "LimitExcept") ]]; then
	echo -e "${txtgrn}5.7 Pass${txtrst}"
else
	echo -e "${txtred}5.7 Fail${txtrst}"
	echo "5.7, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.8 Ensure the HTTP TRACE Method Is Disabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "TraceEnable" >> $a
echo -e "5.8 Manual Check Required"
echo -e "5.8, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.9 Ensure Old HTTP Protocol Versions Are Disallowed \n" >> $a
cat /etc/apache2/apache2.conf | grep "RewriteEngine On\|RewriteCond \%{THE_REQUEST}\|RewriteRule \.\* \- \[F\]\|RewriteOptions Inherit" >> $a
echo -e "5.9 Manual Check Required"
echo -e "5.9, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.10 Ensure Access to .ht* Files Is Restricted\n" >> $a
cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.ht\">\|Require all denied\|<\/FilesMatch>" -n >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.ht\">\|Require all denied\|<\/FilesMatch>" -n) ]]; then
	echo -e "${txtgrn}5.10 Pass${txtrst}"
else
	echo -e "${txtred}5.10 Fail${txtrst}"
	echo "5.10, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.11 Ensure Access to Inappropriate File Extensions Is Restricted\n" >> $a
#find */htdocs -type f -name '*.*' | awk -F. '{print $NF }' | sort -u >> $a
cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.*$\">\|Require all denied\|<\/FilesMatch>" -n >> $a
cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.*\\\.(\|Require all denied\|<\/FilesMatch>" -n >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.ht\">\|Require all denied\|<\/FilesMatch>" -n) ]]; then
	echo -e "${txtgrn}5.11 Pass${txtrst}"
elif [[ -n $(cat /etc/apache2/apache2.conf | grep -e "^<FilesMatch \"\^\\\.*\\\.(\|Require all denied\|<\/FilesMatch>" -n) ]]; then
	echo -e "${txtgrn}5.11 Pass${txtrst}"
else
	echo -e "${txtred}5.11 Fail${txtrst}"
	echo "5.11, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.12 Ensure IP Address Based Requests Are Disallowed\n" >> $a
cat /etc/apache2/apache2.conf | grep "RewriteEngine On\|RewriteCond \%{HTTP_HOST}\|RewriteCond \%{REQUEST_URI}\|RewriteRule \^\.(\.*) \- \[L\,F\]" -n >> $a
echo -e "5.12 Manual Check Required"
echo -e "5.12, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.13 Ensure the IP Addresses for Listening for Requests Are Specified\n" >> $a
cat /etc/apache2/apache2.conf | grep "^Listen" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep "^Listen") ]]; then
	echo -e "${txtgrn}5.13 Pass${txtrst}"
else
	echo -e "${txtred}5.13 Fail${txtrst}"
	echo "5.13, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n5.14 Ensure Browser Framing Is Restricted\n" >> $a
grep -i X-Frame-Options /etc/apache2/apache2.conf >> $a
echo -e "5.14 Manual Check Required"
echo -e "5.14, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.1 Ensure the Error Log Filename and Severity Level Are Configured Correctly\n" >> $a
cat /etc/apache2/apache2.conf | grep "LogLevel\|ErrorLog" >> $a
echo -e "6.1 Manual Check Required"
echo -e "6.1, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.2 Ensure a Syslog Facility Is Configured for Error Logging\n" >> $a
cat /etc/apache2/apache2.conf | grep "ErrorLog \"syslog" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep "ErrorLog \"syslog") ]]; then
	echo  -e "${txtgrn}6.2 Pass${txtrst}"
else
	echo -e "${txtred}6.2 Fail${txtrst}"
	echo "6.2, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.3 Ensure the Server Access Log Is Configured Correctly\n" >> $a
cat /etc/apache2/apache2.conf | grep "^LogFormat\|^CustomLog" >> $a
echo -e "6.3 Manual Check Required"
echo -e "6.3, " >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.4 Ensure Log Storage and Rotation Is Configured Correctly\n" >> $a
echo -e "6.4 Manual Check Required"
echo -e "6.4, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.5 Ensure Applicable Patches Are Applied\n" >> $a
echo -e "6.5 Manual Check Required"
echo -e "6.5, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.6 Ensure ModSecurity Is Installed and Enabled\n" >> $a
sudo apache2ctl -M | grep security2_module >> $a
if [[ -n $(apache2ctl -M | grep security2_module) ]]; then
	echo -e "${txtgrn}6.6 Pass${txtrst}"
else
	echo -e "${txtred}6.6 Fail${txtrst}"
	echo "6.6, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n6.7 Ensure the OWASP ModSecurity Core Rule Set Is Installed and Enabled\n" >> $a
echo -e "6.7 Manual Check Required"
echo -e "6.7, " >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.1 Ensure mod_ssl and/or mod_nss Is Installed\n" >> $a
apache2ctl -M | egrep 'ssl_module|nss_module' >> $a
if [[ -n $(apache2ctl -M | egrep 'ssl_module|nss_module') ]]; then
	echo -e "${txtgrn}7.1 Pass${txtrst}"
else
	echo -e "${txtred}7.1 Fail${txtrst}"
	echo "7.1, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.2 Ensure a Valid Trusted Certificate Is Installed\n" >> $a
echo -e "7.2 Manual Check Required"
echo -e "7.2, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.3 Ensure the Server's Private Key Is Protected\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLCertificateFile\|^SSLCertificateKeyFile" -n >> $a
temp=$(cat /etc/apache2/apache2.conf | grep "^SSLCertificateKeyFile" | cut -d " " -f 2)
ls -al $temp >> $a
echo -e "7.3 Manual Check Required"
echo -e "7.3, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.4 Ensure Weak SSL Protocols Are Disabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLProtocol" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep "^SSLProtocol") ]]; then
	echo -e "${txtgrn}7.4 Pass${txtrst}"
else
	echo -e "${txtred}7.4 Fail${txtrst}"
	echo "7.4, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.5 Ensure Weak SSL/TLS Ciphers Are Disabled\n" >> $a
echo -e "7.5 Manual Check Required"
echo -e "7.5, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.6 Ensure Insecure SSL Renegotiation Is Not Enabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLInsecureRenegotiation" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep "SSLInsecureRenegotiation On") ]]; then
        echo -e "${txtred}7.6 Fail${txtrst}"
        echo "7.6, " >> $b
else
        echo -e "${txtgrn}7.6 Pass${txtrst}"
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.7 Ensure SSL Compression is not Enabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLCompression" >> $a
if [[ -n $(cat /etc/apache2/apache2.conf | grep "^SSLCompression") ]]; then
        echo -e "${txtgrn}7.7 Pass${txtrst}"
else
        echo -e "${txtred}7.7 Fail${txtrst}"
        echo "7.7, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.8 Ensure Medium Strength SSL/TLS Ciphers Are Disabled\n" >> $a
echo -e "7.8 Manual Check Required"
echo -e "7.8, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.9 Ensure All Web Content is Accessed via HTTPS\n" >> $a
echo -e "${txtblu}\n Enter the list of all apache configuration files in the following format :\n${txtrst}"
echo -e "\n Eg: /etc/httpd/conf /etc/httpd/conf.d /etc/httpd/conf_dir2"
#Replace the following directory list with the appropriate list.
#CONF_DIRS="/etc/httpd/conf /etc/httpd/conf.d /etc/httpd/conf_dir2 . . ."
read CONF_DIRS
CONFS=$(find $CONF_DIRS -type f -name '*.conf' )
#Search for Listen directives that are not port :443 or https
IPS=$(egrep -ih '^\s*Listen ' $CONFS | egrep -iv '(:443\b)|https' | cut -d' ' -f2)
#Get host names and ports of all of the virtual hosts
VHOSTS=$(egrep -iho '^\s*<VirtualHost .*>' $CONFS | egrep -io '\s+[A-Z:.0-9]+>$' | tr -d ' >')
URLS=$(for h in $LIPADDR $VHOSTS ; do echo "http://$h/"; done)
#For each of the URL^rs test with curl, and truncate the output to 300 characters
for u in $URLS ; do echo -e "\n\n\n=== $u ==="; curl -fSs $u | head -c 300 ; done >> $a
echo -e "7.9 Manual Check Required"
echo -e "7.9, " >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.10 Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLProtocol TLSv1.2 *" >> $a
if (cat /etc/apache2/apache2.conf | grep "^SSLProtocol TLSv1.2 *" >> $a ); then 
        echo -e "${txtgrn}7.10 Pass${txtrst}"
else 
        echo -e "${txtred}7.10 Fail${txtrst}"
        echo -e "7.10, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.11 Ensure OCSP Stapling Is Enabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^SSLStaplingCache\|^SSLUseStapling" -n >> $a
if (cat /etc/apache2/apache2.conf | grep "^SSLStaplingCache on\|^SSLUseStapling on"  >> $a ); then 
        echo -e "${txtgrn}7.11 Pass${txtrst}"
else 
        echo -e "${txtred}7.11 Fail${txtrst}"
        echo -e "7.11, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.12 Ensure HTTP Strict Transport Security Is Enabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "^Header always set Strict-Transport-Security \"max-age\=600\"" >> $a
if (cat /etc/apache2/apache2.conf | grep "^Header always set Strict-Transport-Security \"max-age\=600\""  >> $a ); then
        echo -e "${txtgrn}7.12 Pass${txtrst}" 
else 
        echo -e "${txtred}7.12 Fail${txtrst}"
        echo -e "7.12, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n7.13 Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled\n" >> $a
echo -e "7.13 Manual Check Required"
echo -e "7.13, " >> $c


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n8.1 Ensure ServerTokens is Set to Prod or ProductOnly\n" >> $a
cat /etc/apache2/apache2.conf | grep "ServerTokens Prod" >> $a
if (cat /etc/apache2/apache2.conf | grep "ServerTokens Prod" >> $a ); then 
        echo -e "${txtgrn}8.1 Pass${txtrst}" 
else 
        echo -e "${txtred}8.1 Fail${txtrst}"
		echo -e "8.1, " >> $b
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n8.2 Ensure ServerSignature Is Not Enabled\n" >> $a
cat /etc/apache2/apache2.conf | grep "ServerSignature Off" >> $a
if (cat /etc/apache2/apache2.conf | grep "ServerSignature Off" >> $a ); then
        echo -e "${txtgrn}8.2 Pass${txtrst}"   
else 
        echo -e "${txtred}8.2 Fail${txtrst}"
        echo -e "8.2, " >> $b
fi

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n8.3 Ensure All Default Apache Content Is Removed\n" >> $a
cat /etc/apache2/apache2.conf | grep "Include conf/extra/httpd-autoindex.conf" >> $a
if (cat /etc/apache2/apache2.conf | grep "Include conf/extra/httpd-autoindex.conf" >> $a) &&
   (cat /etc/apache2/apache2.conf | grep "Alias /icons/ \"/var/www/icons/\"" >> $a ) && 
   (cat /etc/apache2/apache2.conf | grep "<Directory \"/var/www/icons\">" >> $a ); then
        echo -e "${txtred}8.3 Fail${txtrst}"
        echo -e "8.3, " >> $b  
else 
        echo -e "${txtgrn}8.3 Pass${txtrst}"  
fi


echo -e "\n==========================================================================================\n" >> $a
echo -e "\n8.4 Ensure ETag Response Header Fields Do Not Include Inodes\n" >> $a
cat /etc/apache2/conf-enabled/security.conf | grep "FileETag" >> $a
if (cat /etc/apache2/conf-enabled/security.conf | grep "FileETag" >> $a); then
        echo -e "${txtred}8.4 Fail${txtrst}"
        echo -e "8.4, " >> $b
else
        echo -e "${txtgrn}8.4 Pass${txtrst}"  
fi  


echo -e "\n=======================================================================\n" >> $a
echo -e "\n9.1 Ensure the TimeOut Is Set to 10 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "Timeout"  >> $a
echo -e "9.1 Manual Check Required"
echo -e "9.1, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n9.2 Ensure KeepAlive Is Enabled\n" >> $a
if (cat /etc/apache2/apache2.conf | grep "KeepAlive On" >> $a);  then 
        echo -e "${txtgrn}9.2 Pass${txtrst}"  
else
        echo -e "${txtred}9.2 Fail${txtrst}" 
        echo -e "9.2, " >> $b
fi

echo -e "\n=======================================================================\n" >>  $a
echo -e "\n9.3 Ensure MaxKeepAliveRequests is Set to a Value of 100 or Greater\n" >> $a
cat /etc/apache2/apache2.conf | grep "MaxKeepAliveRequests" >> $a  
echo -e "9.3 Manual Check Required"
echo -e "9.3, " >> $c


echo -e "\n=======================================================================\n" >>$a
echo -e "\n9.4 Ensure KeepAliveTimeout is Set to a Value of 15 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "KeepAliveTimeout" >> $a
echo -e "9.4 Manual Check Required"
echo -e "9.4, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n9.5 Ensure the Timeout Limits for Request Headers is Set to 40 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "RequestReadTimeout" >> $a
echo -e "9.5 Manual Check Required"
echo -e "9.5, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n9.6 Ensure Timeout Limits for the Request Body is Set to 20 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "RequestReadTimeout" >> $a
echo -e "9.6 Manual Check Required"
echo -e "9.6, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n10.1 Ensure the LimitRequestLine directive is Set to 512 or less\n" >> $a
cat /etc/apache2/apache2.conf | grep "LimitRequestline" >> $a
echo -e "10.1 Manual Check Required"
echo -e "10.1, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n10.2 Ensure the LimitRequestFields Directive is Set to 100 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "LimitRequestFields" >> $a
echo -e "10.2 Manual Check Required"
echo -e "10.2, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n10.3 Ensure the LimitRequestFieldsize Directive is Set to 1024 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "LimitRequestFieldsize" >> $a
echo -e "10.3 Manual Check Required"
echo -e "10.3, " >> $c

echo -e "\n==========================================================================================\n" >> $a
echo -e "\n10.4 Ensure the LimitRequestBody Directive is Set to 102400 or Less\n" >> $a
cat /etc/apache2/apache2.conf | grep "LimitRequestBody" >> $a
echo -e "10.4 Manual Check Required"
echo -e "10.4, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n${txtblu}11 - Please ensure SELinux is install and enable${txtrst}" 
echo -e "\n11.1 Ensure SELinux Is Enabled in Enforcing Mode\n" >> $a
if (cat /etc/selinux/config | grep "SELINUX=enforcing" >> $a); then
        echo -e "${txtgrn}11.1 Pass${txtrst}"   
else
        echo -e "${txtred}11.1 Fail${txtrst}" 
        echo -e "11.1, " >> $b
fi 

echo -e "\n=======================================================================\n" >>  $a
echo -e "\n11.2 Ensure Apache Processes Run in the httpd_t Confined Context\n" >> $a
ps -eZ | grep httpd >> $a
ps -eZ | grep apache2 >> $a
echo -e "11.2 Manual Check Required"
echo -e "11.2, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n11.3 Ensure the httpd_t Type is Not in Permissive Mode\n" >> $a
semodule -l | grep permissive_httpd_t >> $a
echo -e "11.3 Manual Check Required"
echo -e "11.3, " >> $c


echo -e "\n=======================================================================\n" >> $a
echo -e "\n11.4 Ensure Only the Necessary SELinux Booleans are Enabled\n" >> $a
getsebool -a | grep httpd_ | grep '> on' >> $a
echo -e "\n" >> $a
semanage boolean -l | grep httpd_ | grep -v '(off , off)' >> $a



echo -e "\n=======================================================================\n" >> $a
echo -e "\n12.1 Ensure the AppArmor Framework Is Enabled\n" >> $a
aa-status --enabled && echo Enabled >> $a
echo -e "12.1 Manual Check Required"
echo -e "12.1, " >> $c


echo -e "\n======================================================================= \n" >> $a
echo -e "\n12.2 Ensure the Apache AppArmor Profile Is Configured Properly\n" >> $a
echo -e "12.2 Manual Check Required\n"
echo -e "12.2, " >> $c


echo -e "\n=======================================================================\n" >> $a


echo -e Check the Output on result.txt
echo -e Check all failed on fail.txt
echo -e Check all require manual check on manual.txt
