#!/usr/bin/env python3


import xml.etree.cElementTree as ET
from libnmap.parser import NmapParser
import os as OS
import argparse
from random import seed
from random import randint
import glob
import re
import subprocess
import base64

# used for searchsploit, helps to narrow results [search_string, replace_string]
version_filter = [['ftpd','ftp'],['Windows',''],['httpd','http'],['Powered by Apache',''],[';',''],['smbd','']]

# used to highlight keywords in results
##  aray def = [ regex to color, color ,filname string to match],
HighlighterArray = [
	# script titles
	[r'(^\|(\s|\_)[a-z]*-.*?:)',"#ffff00","nmap"],
	# open ports
	[r'(^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))(/tcp\s*open|/udp\s*open).*\n)',"#00cd00","nmap"],
	# filtered ports
	[r'(^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))(/tcp\s*filtered|/udp\s*filtered).*\n)',"#ff0000","nmap"],
	# banners
	[r'(^\|(\s|\_)banner?:)',"#ffff00","nmap"],
	[r'(^\|\s*VULNERABLE?:)',"#ff4300","nmap"],

	# gobuster
	[r'(^http.*\(Status: 200\).*\n)',"#00cd00","gobust"],
	[r'(^http.*\(Status: 403\).*\n)',"#ff0000","gobust"],
	[r'(\+ OSVDB-.*?:)',"#ffff00","nikto"],
	]


EXFIL_TEMPLATE = """
Windows
    Look for secrets
        ☐ cd c:\\ & dir *secret* /s /a /p

    Dump creds
        ☐ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

        ☐ C:\\> procdump.exe -accepteula -ma lsass.exe c:\\windows\\temp\\lsass.dmp 2>&1
        ☐ C:\\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit

        ☐ C:\\> wce.exe -w, pwdump.exe, fgdump.exe

        ☐ net use z: \\\\netbiosname\\SYSVOL  ;  dir /s Groups.xml  ;  type Groups.xml  (then use gpp-decrypt on kali)


Linux
    Look for secrets
        ☐ find / -type f -name "*secret*"

    Dump Creds
        ☐ get copies of /etc/passwd /etc/shadow for cracking

"""

CLEANUP_TEMPLATE = """
Windows
    Check logs for local ip

    Check for files we have dropped
        ☐ c:\\tmp
        ☐ c:\\windows\\temp

Linux
    Check log files
         ☐ grep -R $local_ip
         ☐ sed  '/$local_ip/d' logfile

    Check for files we have dropped.
     ☐ /dev/shm
     ☐ /tmp
"""
def InsertImage(element,image):
	with open(image,'rb') as file:
		data = file.read()
	# rtline = ET.SubElement(element, "rich_text")
	rtpng = ET.SubElement(element,"encoded_png")
	rtpng.set('char_offset','0')
	rtpng.text = base64.b64encode(data).decode()

	# <rich_text>
	# 	<encoded_png char_offset="0">
	# 	Base64(image_file)
	# </encoded_png>
	# </node>

#service is an libnmap.host.service object
def DoSearchSploit(service):
	HEADER = '\033[95m'
	GREEN = '\033[92m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'

	version = ''
	outfile = "%s%s_%s_%s_searchsploit.ansi" %(ScansDir,service.protocol,service.port,service.service) # "tcp_49155_rpc_nmap.txt"
	portproto = "%s/%s/%s" %(service.port,service.protocol,service.service)
	banner = service.banner  # strip everything after extrainfo:
	if banner.strip() == '':
		return
	banner = banner[9:] # strip product: from begin


	match = re.findall(r'([a-z\d_-]+):',banner) # find all words that end in :
	if match:
		product = banner[0:re.search(match[0],banner).start(0)] #match from start of banner to first word that ends in:
	else:
		product = banner[0:]

	for i,val in enumerate(match): # get version: str if exsists
		if val == "version":
			try:
				version = banner[re.search('version:',banner).end(0):re.search(match[i+1],banner).start(0)]
			except:
				version = ''

	# replaces words in version string with words from search  filter (better results)
	filtertest= product.split(' ')
	prodfinal = ''
	for i,val in enumerate(version_filter):
		srch = val[0]
		repl = val[1]
		if srch in product:
			product = product.replace(srch,repl).rstrip().lstrip()


	if len(product.strip()) < 3 or len(product.strip()) > 50:
		return

	ss = subprocess.check_output(['searchsploit',product]).decode()
	# match version and add ansi tags
	verarray = []
	version = version.strip()
	if version != '':
		if ss.find(version) != -1:
			verarray.append(version)
			ss = ss.replace(version,BOLD + GREEN + version + ENDC)
		else:
			run = True
			while run:  # this loop strips a decimal place each pass and checks ss to match greatest version possible
				match = version.find('.')
				if match != -1:
					stringlength=len(version) # calculate length of the list
					revstr=version[stringlength::-1] #resere the string
					match = revstr.find('.') # match first . (last . reversed)
					dropped = revstr[match+1:] # cut off last decimal
					stringlength=len(dropped) # calculate length of the list
					newver = dropped[stringlength::-1] # reverse string to normal
					if len(newver) == 1:
						run = False
						break

					version_match = ss.find(newver)

					if version_match != -1:
						verarray.append(newver)
						ss = ss.replace(newver,BOLD + GREEN + newver + ENDC)
						run = False
						break

					version = newver
				else:
					run = False
					break



	output = "-------------------------------------------------------------------------------------------------------------------------------\n"
	output += "Service: %s\n" %portproto
	output += "Banner: %s" %banner
	output += "\n\nSearch Words: %s (RED)" %product
	output += "\nVersions Highlighted: %s (GREEN)" %verarray
	output += "\n"
	if len(ss) == 42:
		output += "---------------------------------------------------------------------------------------------------------------------------\n"
	output += ss

	with open(outfile,'w+') as OUT:
		OUT.seek(0)
		OUT.write(output)


# imports an ansi color file. only does simple ansi formatting.  ***** requires ansifilter
def ImportAnsiFile(element,filename):
	print("Importing ANSI File: %s" %filename)
	RTF_VALS = {
	        'fg': 0,
	        'bg': 0,
	        'bold': False,
	        'italic':False
	        }
	ESCAPE_PATTERN = re.compile('(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]') # matches asci escape sequnces

	def LookupCodes(ansicode): # use ansifilter to match ansi code to html color
		ss = str(subprocess.check_output("echo \"%s hello\" |ansifilter -H|grep hello" %ansicode, shell=True))
		if "span" not in ss:
			return None
		data = re.search('(".*?")',ss).group()
		data = data.strip('"').rstrip(';')
		return data.split(';')


	def Ansi2RTF(ansicode):
		cur_rtf = RTF_VALS
		cur_rtf['fg'] = 0
		cur_rtf['bg'] = 0
		cur_rtf['bold'] = False
		cur_rtf['italic'] = False


		format_str = LookupCodes(ansicode)
		if format_str == None:
			return cur_rtf

		for i in format_str:
			cur_set = i.split(':')
			if cur_set[0] == 'color':
				cur_rtf['fg'] = cur_set[1]

			if cur_set[0] == 'background-color':
				cur_rtf['bg'] = cur_set[1]


		return cur_rtf

	def PrintRTF(element,txt,rtf_vals):
		rtline = ET.SubElement(element, "rich_text")
		rtline.text=txt
		if rtf_vals['fg'] != 0:
			rtline.set("foreground",rtf_vals['fg'])

		if rtf_vals['bg'] != 0:
			rtline.set("background",rtf_vals['bg'])

		if rtf_vals['bold'] == True:
			rtline.set("weight","heavy")

		if rtf_vals['italic'] == True:
			rtline.set("style","italic")


	with open(filename) as file:
		txt=file.read()
		cur_pos = 0
		cur_buf =''
		cur_rtf_val = RTF_VALS

		if not re.search(ESCAPE_PATTERN,txt):# no escapes so just normal text
			PrintRTF(element,txt,cur_rtf_val)
			return

		for i in re.finditer(ESCAPE_PATTERN,txt): # replace escapes richtext wont use
			if not i.group().endswith('m'):
				txt = txt.replace(i.group(),'')


		for match in re.finditer(ESCAPE_PATTERN,txt):
			cur_buf = txt[cur_pos:match.start()]

			if cur_buf != '':
				PrintRTF(element,cur_buf,cur_rtf_val)
			rtf_vals = Ansi2RTF(match.group())

			cur_pos = match.end()

		PrintRTF(element,txt[cur_pos:],RTF_VALS)


# this function handles colorizing files
def ParseFile(element,filename):

	if ScansDir not in filename:
		filename = "%s%s" %(ScansDir,filename)

	basename, file_extension = OS.path.splitext(filename)
	colorize=False
	if file_extension == ".ansi":
		# print("%s   %s" %(filename,file_extension))
		ImportAnsiFile(element,filename)
		return

	if file_extension == ".png":
		InsertImage(element,filename)
		return

	if args.color == True:
		# test if its a file we need to color
		for grp in HighlighterArray:
			if grp[2] in str(filename):
				colorize=True
	else:
		colorize = False

	if colorize == True:

		with open(filename) as file:
			data = file.readlines()
			tmptext = ''

			for line in data:
				curexp =''
				color=''
				found = ''

				for curexpgrp in HighlighterArray:
					curexp =curexpgrp[0]
					color=curexpgrp[1]
					found = re.search(curexp,line)
					if found:
						break

				if found:
					# print what we have stored
					ET.SubElement(element, "rich_text").text=tmptext
					tmptext = ''

					splt = []
					splt = re.split(curexp,line)
					# # add what we have with color
					tmptext += splt[0]
					rtline = ET.SubElement(element, "rich_text")
					rtline.text=splt[1]
					rtline.set("foreground",color)

					# add the rest of the line
					if splt[-1]:
						tmptext += splt[-1]

				else:
					tmptext += line
						# clear tmptext
				ET.SubElement(element, "rich_text").text=tmptext
				tmptext = ''

			# done with loop add whats left
			if tmptext:
				ET.SubElement(element, "rich_text").text=tmptext

	# non color file
	else:
		with open(filename) as file:
			text = file.read()
			ET.SubElement(element, "rich_text").text=text




parser = argparse.ArgumentParser()
parser.add_argument("-c", "--color", action="store_true",help="Colorize certian lines")
parser.add_argument("-o", "--out", action="store",help="Output filename (default is cherrycon.ctd)")

parser.add_argument("dir", help="AutoRecon directory")
args = parser.parse_args()

# seed random number generator
seed(152)


ReconDir = args.dir
ReconDir = ReconDir.rstrip('//')
ScansDir = "%s/scans/" %ReconDir
XMLdir = "%s/xml/" %ScansDir


if not OS.path.exists(ReconDir):
	print("[!] Error: AutoRecon directory doesn't exist !")
	exit(1)

if not OS.path.exists(XMLdir):
	print("[!] Error: AutoRecon XML directory doesn't exist !")
	exit(1)

if not OS.path.exists(ScansDir):
	print("[!] Error: AutoRecon scans directory doesn't exist !")
	exit(1)

if args.out:
    ctdfile = args.out
else:
    ctdfile = "%s/cherrycon.ctd" %ReconDir

AllPorts=[]
AllServiceVersions=[]

#*** parse and combine ports
if OS.path.exists("%s_full_tcp_nmap.xml" %XMLdir):
	try:
		rep = NmapParser.parse_fromfile("%s_full_tcp_nmap.xml" %XMLdir)


		for _host in rep.hosts:
			if _host.is_up():
				try:
					if _host.hostnames[0] != '':
						targetname = "%s (%s)" %(_host.hostnames[0],_host.address)
					else:
						targetname = _host.address
				except:
					targetname = _host.address

				for  _service in _host.services:
					if _service.open():
						AllPorts.append("%s/%s/%s" %(_service.port,_service.protocol,_service.service))
						AllServiceVersions.append(_service.banner)
						DoSearchSploit(_service)
	except:
		print("Failed to parse %s_full_tcp_nmap.xml" %XMLdir)


if OS.path.exists("%s_quick_tcp_nmap.xml" %XMLdir):
	try:
		rep = NmapParser.parse_fromfile("%s_quick_tcp_nmap.xml" %XMLdir)
		for _host in rep.hosts:
			if _host.is_up():
				try:
					if _host.hostnames[0] != '':
						targetname = "%s (%s)" %(_host.hostnames[0],_host.address)
					else:
						targetname = _host.address
				except:
					targetname = _host.address

				for  _service in _host.services:
					if _service.open():
						AllPorts.append("%s/%s/%s" %(_service.port,_service.protocol,_service.service))
						AllServiceVersions.append(_service.banner)
	except:
		print("Failed to parse %s_quick_tcp_nmap.xml" %XMLdir)

if OS.path.exists("%s_top_20_udp_nmap.xml" %XMLdir):
	try:
		rep = NmapParser.parse_fromfile("%s_top_20_udp_nmap.xml" %XMLdir)
		for _host in rep.hosts:
			if _host.is_up():
				try:
					if _host.hostnames[0] != '':
						targetname = "%s (%s)" %(_host.hostnames[0],_host.address)
					else:
						targetname = _host.address
				except:
					targetname = _host.address

				for  _service in _host.services:
					if _service.open():
						AllPorts.append("%s/%s/%s" %(_service.port,_service.protocol,_service.service))
						AllServiceVersions.append(_service.banner)
						DoSearchSploit(_service)
	except:
		print("Failed to parse %s_top_20_udp_nmap.xml" %XMLdir)

# remove duplicates
unique_list = []
for x in AllPorts:
	# check if exists in unique_list or not
	if x not in unique_list and x != "":
		unique_list.append(x)

AllPorts = unique_list


unique_list2 = []
for x in AllServiceVersions:
	# check if exists in unique_list or not
	x = x.replace("product: ","")
	if "ostype:" in x:
		x =  x.split("ostype: ")[0]
	if "extrainfo: " in x:
		x =  x.split("extrainfo: ")[0]

	if x not in unique_list2 and x != "":
		unique_list2.append(x)

AllServiceVersions = unique_list2

root = ET.Element("cherrytree")
host = ET.SubElement(root, "node", custom_icon_id="14", foreground="", is_bold="False", name=targetname, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
sysinfo = ET.SubElement(host, "node", custom_icon_id="12", foreground="", is_bold="False", name="System Details", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

r_enum = ET.SubElement(host, "node", custom_icon_id="22", foreground="", is_bold="False", name="Remote Enumeration", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
portnode = ET.SubElement(r_enum, "node", custom_icon_id="38", foreground="", is_bold="False", name="Ports", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))


for port in AllPorts:
	service = ET.SubElement(portnode, "node", is_bold="False", name=str(port), prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
	tPort=port.split('/')



	tmpFileArray = glob.glob("%s%s_%s_*" %(ScansDir,tPort[1],tPort[0]))

	if tmpFileArray:
		# portscansnode = ET.SubElement(service, "node", custom_icon_id="44", foreground="", is_bold="False", name="Scans", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

#  parse files for each service
		for filename in tmpFileArray:
			basename, file_extension = OS.path.splitext(filename)
			# if file_extension == ".gnmap" or file_extension == ".xml":
			# 	continue

			nodenamearr = filename.split('_')

			if len(nodenamearr) == 4:
				nodename = "_"
				nodename = nodename.join(nodenamearr[2:])
			else:
				nodename = "_"
				nodename = nodename.join(nodenamearr[-3:])


			portscanfile = ET.SubElement(service, "node", custom_icon_id="18", foreground="", is_bold="False", name=nodename, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
			ParseFile(portscanfile,filename)

####################################

scansnode = ET.SubElement(r_enum, "node", custom_icon_id="44", foreground="", is_bold="False", name="Scans", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

#  parse  global files
for filename in OS.listdir(ScansDir):
	basename, file_extension = OS.path.splitext(filename)

	if not filename.startswith("udp") and not filename.startswith("tcp") and not OS.path.isdir("%s%s" %(ScansDir,filename)):

		scanfile = ET.SubElement(scansnode, "node", custom_icon_id="18", foreground="", is_bold="False", name=filename, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
		ParseFile(scanfile,filename)

		continue
	else:
		continue


#######################
r_service_ver = ET.SubElement(r_enum, "node", custom_icon_id="12", foreground="", is_bold="False", name="Software Versions", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
tmptext = ""
for fp in AllServiceVersions:
	tmptext += fp + "\n"
ET.SubElement(r_service_ver, "rich_text").text=tmptext

r_vulns = ET.SubElement(r_enum, "node", custom_icon_id="43", foreground="", is_bold="False", name="Remote Vulnerabilites", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

foothold = ET.SubElement(host, "node", custom_icon_id="41", foreground="", is_bold="False", name="Foothold", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
l_enum = ET.SubElement(host, "node", custom_icon_id="21", foreground="", is_bold="False", name="Local Enumeration", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
l_service_ver = ET.SubElement(l_enum, "node", custom_icon_id="12", foreground="", is_bold="False", name="Software Versions", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
l_vulns = ET.SubElement(l_enum, "node", custom_icon_id="43", foreground="", is_bold="False", name="Local Vulnerabilites", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

escalate = ET.SubElement(host, "node", custom_icon_id="41", foreground="", is_bold="False", name="Escalation", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

users = ET.SubElement(host, "node", custom_icon_id="42", foreground="", is_bold="False", name="Users", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

loot = ET.SubElement(host, "node", custom_icon_id="24", foreground="", is_bold="False", name="Loot", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
creds = ET.SubElement(loot, "node", custom_icon_id="42", foreground="", is_bold="False", name="Credentials", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
proof = ET.SubElement(loot, "node", custom_icon_id="18", foreground="", is_bold="False", name="Proof", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
secrets = ET.SubElement(loot, "node", custom_icon_id="10", foreground="", is_bold="False", name="Secrets", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))

exfil = ET.SubElement(host, "node", custom_icon_id="9", foreground="", is_bold="False", name="Exfil", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
ET.SubElement(exfil, "rich_text").text=EXFIL_TEMPLATE
cleanup_todo = ET.SubElement(exfil, "node", custom_icon_id="18", foreground="", is_bold="False", name="Cleanup-Todo", prog_lang="custom-colors", readonly="False", tags="", unique_id=str(randint(0,10000)))
ET.SubElement(cleanup_todo, "rich_text").text=CLEANUP_TEMPLATE

tree = ET.ElementTree(root)
tree.write(ctdfile)

exit()
