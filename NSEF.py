import BeautifulSoup
import xml.etree.ElementTree as ET
import urllib2
from termcolor import colored
import sys

def LookBIDexploit(urlBID,vuln):
	try:		
		url = 'http://www.securityfocus.com/bid/'+urlBID+'/exploit'	
		request = urllib2.Request(url)
		response = urllib2.urlopen(request)
		http_response = response.read()
		soup2 = BeautifulSoup.BeautifulSoup(http_response)
		for link in soup2.findAll("a"):
			if  "/data/vulnerabilities/exploits/" in link.get("href"):
				print colored(vuln, 'red', attrs=['bold'])				
				print soup2.span.string
				print url + " - Exploit available"
				print ""
				break	
	except:
		pass


def Extractor():
	print colored("""
		|------------------------------------------|
		     Nessus Security Focus Exploit finder
		|------------------------------------------|
		""", 'green', attrs=['bold'])
	if len(sys.argv) < 2:
		print colored("usage: python NSEF.py report.nessus")
	else:
		tree = ET.parse(sys.argv[1])
		root = tree.findall('.//ReportItem')	
		for child in root:
			vuln =  child.attrib['pluginName'] + " - port: " + child.attrib['port']
			for bid in child:
				if "bid" in bid.tag:
					LookBIDexploit(bid.text,vuln)
	
Extractor()

