from scapy.all import *

maclist = []
encrypted = ''

print "Ch\t" + "Enc\t" + "Mac Adress\t\t" + "SSID"
print "---\t" + "---\t" + "--------------\t\t" + "-------"

def collectInfo(packet):
	if packet.haslayer(Dot11Beacon):
		mac=packet.addr2
		ssid=packet.info
		chan=str(ord(packet[Dot11Elt:3].info)) #channel number
		capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
		enc = capability.split('+') #if network encrypted
		if "privacy" in enc:
			encrypted='Y' #Yes
		else:
			encrypted='N' #No
		if mac not in maclist and '\x00' not in ssid:
			maclist.append(mac)
			print chan+ "\t"+ encrypted +"\t" + mac + "\t" + ssid

sniff(iface="wlan0mon",count=0, prn=collectInfo)
