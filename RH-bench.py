import subprocess
import re
import sys

httpdroot = "/etc/httpd/"
linuxFilePathPattern = re.compile("(^(/[^/ ]*)+/?:)", re.M)
result = {}

#----2.2----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'log_config'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()

if ("(shared)" in output.stdout.decode('UTF-8') or "(static)" in output.stdout.decode('UTF-8')):
	result["2.2"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'log_config', httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.2"] = "WARN - Enable modules at {}".format(mods)

#----2.3----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', ' dav_[[:print:]]+module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.3"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', ' dav_[[:print:]]+module', httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.3"] = "WARN - Disable modules at {}".format(mods)

#----2.4----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('egrep', 'status_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.4"] = "OK"
else:
	output = subprocess.run(['egrep', '-ir', 'status_module', httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.4"] = "WARN - Disable modules at {}".format(mods)

#----2.5----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'autoindex_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.5"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'autoindex_module',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.5"] = "WARN - Disable modules at {}".format(mods)

#----2.6----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'proxy_'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.6"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'proxy_',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.6"] = "WARN - Disable modules at {}".format(mods)

#----2.7----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'userdir_'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.7"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'userdir_',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.7"] = "WARN - Disable modules at {}".format(mods)

#----2.8----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('egrep', 'info_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.8"] = "OK"
else:
	output = subprocess.run(['egrep', '-ir', 'info_module',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.8"] = "WARN - Disable modules at {}".format(mods)

#----2.9 - Basic----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'auth_basic_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.9-Basic"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'auth_basic_module',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.9-Basic"] = "WARN - Disable modules at {}".format(mods)

#----2.9 - Digest----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'auth_digest_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (not output.stdout.decode('UTF-8')):
	result["2.9-Digest"] = "OK"
else:
	output = subprocess.run(['grep', '-ir', 'auth_digest_module',httpdroot], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	mods = re.findall(linuxFilePathPattern, output)
	mods = [i[0] for i in mods]
	mods = list(dict.fromkeys(mods))
	result["2.9-Digest"] = "WARN - Disable modules at {}".format(mods)

#----3.1----
okflag = True
output = subprocess.run(['grep', '-i', '^User',httpdroot+'conf/httpd.conf'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if output:
	apacheuser = output.split(" ")[1].strip()

	output = subprocess.run(['grep', '-i', '^Group',httpdroot+'conf/httpd.conf'], stdout=subprocess.PIPE)
	output = output.stdout.decode('UTF-8')
	if output:
		apachegroup = output.split(" ")[1].strip()
		if apacheuser and apachegroup:
			output = subprocess.run(['grep', '^UID_MIN', '/etc/login.defs'], stdout=subprocess.PIPE)
			uid1 = output.stdout.decode('UTF-8')
			uid1 = uid1.split()[1]
			output = subprocess.run(['id', apacheuser], stdout=subprocess.PIPE)
			uid2 = output.stdout.decode('UTF-8')
			uidpattern = re.compile("uid=(\d+)\(")
			uid2 = re.findall(uidpattern, uid2)[0]
			if int(uid2) >= int(uid1):
				okflag = False
		else:
			okflag = False
	else:
		okflag = False	
else:
	okflag = False


if okflag:
	result["3.1"] = "OK"
else:
	result["3.1"] = "WARN - Refer to Benchmark Document"

#----3.2----
output = subprocess.run(['grep', 'apache', '/etc/passwd'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if "/sbin/nologin" in output or "/dev/null" in output:
	result["3.2"] = "OK"
else:
	result["3.2"] = "WARN - Change the apache account to use the nologin shell"

#----3.3----
output = subprocess.run(['passwd', '-S', 'apache'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if "(Password locked.)" in output:
	result["3.3"] = "OK"
else:
	result["3.3"] = "WARN - Use passwd to lock the apache account."

#----3.4----
output = subprocess.run(['find', httpdroot, '!', '-user', 'root' , '-ls'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if not output:
	result["3.4"] = "OK"
else:
	result["3.4"] = "WARN - Set ownership of apache/httpd directories to root"

#----3.5----
output = subprocess.run(['find', httpdroot, '!', '-path', httpdroot+'htdocs', '-prune', '-o', '!', '-group', 'root', '-ls'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if not output:
	result["3.5"] = "OK"
else:
	result["3.5"] = "WARN - Set ownership of apache/httpd directories to root"

#----3.6----
output = subprocess.run(['find', '-L', httpdroot, '!', '-type', 'l', '-perm', '/o=w', '-ls'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if not output:
	result["3.6"] = "OK"
else:
	result["3.6"] = "WARN - Remove other write access on the apache/httpd directories."

#----3.11----
output = subprocess.run(['find', '-L', httpdroot, '!', '-type', 'l', '-perm', '/g=w', '-ls'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
if not output:
	result["3.11"] = "OK"
else:
	result["3.11"] = "WARN - Remove group write access on the apache/httpd directories."

#----3.12----
output = subprocess.run(['grep', '^Group', httpdroot+'conf/httpd.conf'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
group = output.split()[1]
output = subprocess.run(['grep', 'DocumentRoot \"', httpdroot+'conf/httpd.conf'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
docroot = output.split()[1].replace('\"','')
output = subprocess.run(['find', '-L', docroot, '-group', group, '-perm', '/g=w', '-ls'], stdout=subprocess.PIPE)
output = output.stdout.decode('UTF-8')
print(output)
if not output:
	result["3.11"] = "OK"
else:
	result["3.11"] = "WARN - remove group write access on the $DOCROOT directories and files with the apache group"

#----6.6----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', 'security2_module'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
#print(output.stdout.decode('UTF-8'))
if (output.stdout.decode('UTF-8')):
	result["6.6"] = "OK"
else:
	result["6.6"] = "WARN - Install the mod_security2 module"

#----7.1----
ps = subprocess.Popen(('httpd', '-M'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('egrep', '\'ssl_module|nss_module\''), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
if (output.stdout.decode('UTF-8')):
	result["7.1"] = "OK"
else:
	result["7.1"] = "WARN - Install the mod_ssl module"

#----11.1----
ps = subprocess.Popen(('sestatus'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = subprocess.run(('grep', '-i', 'mode'), stdin=ps.stdout, stdout=subprocess.PIPE)
ps.wait()
output = "".join(output.stdout.decode('UTF-8').split())
if ("Currentmode:enforcingModefromconfigfile:enforcing" in output):
	result["11.1"] = "OK"
else:
	result["11.1"] = "WARN - edit the file /etc/selinux/config and set the value of SELINUX as enforcing and reboot the system"

#----RESULTS----

for i in result:
 print("{}:{}".format(i,result[i]))
