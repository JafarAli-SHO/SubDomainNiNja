# SubDomainNiNja
SubDomainNiNja is a powerful and comprehensive subdomain enumeration tool designed for cybersecurity professionals and enthusiasts. This tool leverages multiple sources and recursive techniques to provide an in-depth discovery of subdomains associated with a given domain By integrating APIs from VirusTotal SecurityTrails and DNSDumpster

install these libraries using the below command 
# pip install requests tldextract argparse logging
# Usage 
Add virustotal and security trails api key to the script in the def main () function
# Python3 SubDomainNiNja -d target_domain 
for recursively subdomain enumerantion use -r default is 1 
# Python3 SubDomainNiNja -d target_domain -r 2
