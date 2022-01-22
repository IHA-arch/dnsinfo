import subprocess
import threading
import requests
import socket
import json
import os
from time import sleep
from random import randrange

def root_permission():
    user = str(subprocess.check_output('whoami',shell=True),'utf-8')
    user=user.replace('\n','')
    if ( user != 'root'):
        print("\033[1;32mPlease run as root")
        exit()

root_permission()

def header(i, name):
    if len(i)>=6 and len(i)<12:
        print("\033[1;37m {} \t\t \033[1;31m {}".format(i, name))
    elif len(i)<6:
        print("\033[1;37m {} \t\t\t \033[1;31m {}".format(i, name))
    else:
        print("\033[1;37m {} \t \033[1;31m {}".format(i, name))

def banner(k):
    print('\033[1;3{}m mmmm   mm   m  mmmm         mmmmm  mm   m mmmmmm  mmmm \n #   "m #"m  # #"   "          #    #"m  # #      m"  "m\n #    # # #m # "#mmm           #    # #m # #mmmmm #    #\n #    # #  # #     "#  """     #    #  # # #      #    #\n #mmm"  #   ## "mmm#"        mm#mm  #   ## #       #mm#\n'.format(k))

def about():
    print('\n\033[1;31mCreate By     \t\t\t        \033[1;36m>\033[1;37m \tIHA\n\033[1;31mWritten Language\t        \t\033[1;36m>\033[1;37m \tPython3 & shell\n\033[1;31mSupported Operation System\t\t\033[1;36m>\033[1;37m \tKali Linux\n\033[1;31mPurpose\t\t\t\t\t\033[1;36m>\033[1;37m\tDomain information checking\n\033[1;31mGitHub \t\t\t\t\t\033[1;36m>\033[1;37m\thttps://github.com/IHA-arch\n')

def api_key():
    path='/usr/share/DNSInfo_IHA/APIkey'
    key=open(path,'r')
    api=key.read()
    api=api.replace(' ','')
    return api

current_pid=os.getpid()

def network_connection(current_pid):
    condition=True
    i=0
    while condition:
        try:
            scanner=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            scanner.connect_ex(('www.google.com',80))
        except:
            print("\033[1;31mNo Internet Connection found!!\nExiting...\033[0;0m")
            command="kill {}".format(current_pid)
            os.system(command)


network_thread = threading.Thread(target=network_connection,args=(current_pid,))
network_thread.start()

def Main_Menu():
    i="about"
    name="Tool Creater information"
    header(i, name)
    i="help"
    name="Show Help"
    header(i, name)
    i='add api <api-key>'
    name='Add API Key'
    header(i, name)
    i='api'
    name='See current API Key'
    header(i, name)
    i='create'
    name='Accout creation information'
    header(i, name)
    i="1"
    name="Reverse DNS Lookup"
    header(i, name)
    i="2"
    name="DNS Propagation"
    header(i, name)
    i="3"
    name="DNS Record"
    header(i, name)
    i="4"
    name="HTTP Header"
    header(i, name)
    i="5"
    name="GOOGLE Page Rank"
    header(i, name)
    i="6"
    name="IP Histroy"
    header(i, name)
    i="7"
    name="Trace Route"
    header(i, name)
    i="8"
    name="IP Locate"
    header(i, name)
    i="9"
    name="Port Scanner"
    header(i, name)
    i="10"
    name="Reverse MX Lookup"
    header(i, name)
    i="11"
    name="Reverse NS Lookup"
    header(i, name)
    i="12"
    name="Free Email Lookup"
    header(i, name)
    i="13"
    name="IP Lookup"
    header(i, name)
    i="clear"
    name="Clear Screen"
    header(i, name)
    i="exit"
    name="Exit DNS-INFO"
    header(i, name)

def check_domain_work(domain):
    try:
        socket.inet_aton(domain)
        check=domain
    except socket.error:
        try:
            check=socket.gethostbyname(domain)
            print("\033[1;39mDomain IP::\033[1;33m{}".format(check))
            sleep(0.3)
        except:
            print("\033[0;0mInvalid Domain::\033[1;4;31m{}\033[0;0m".format(domain))
            check=''
    return check

def port_scanner(domain):
    url="https://api.viewdns.info/portscan/?host={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;31mPORT\t\tTYPE\t\t\tSTATUS\033[1;39m")
            scanner = get_request.json()
            for key in scanner['response']['port']:
                print(key['number'],end='')
                print("\t\t",key['service'],end='')
                if len(key['service'])<6:
                    print("\t\t\t",key['status'])
                elif len(key['service'])>6:
                    print("\t\t",key['status'])
                else:
                    print("\t\t\t",key['status'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def ip_lookup(domain):
    url="https://api.viewdns.info/reverseip/?host={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            lookup=get_request.json()
            if lookup['response']['domain_count'] == '0':
                print("\033[0;0mThere are no domain hosted on this server")
            else:
                print("\033[0;0mThere are \033[1;31m{}\033[0;0m domains hosted on this server".format(lookup['response']['domain_count']))
                sleep(0.5)
                print("\033[1;31mLast Resolved Date             Domain\033[1;39m")
                for key in lookup['response']['domains']:
                    print(key['last_resolved'],end='')
                    print("\t\t",key['name'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def mx_lookup(domain):
    url="https://api.viewdns.info/reversemx/?mx={}&apikey={}&output=json".format(domain, api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;39m",end='')
            scanner=get_request.json()
            if 'error' in scanner['response']:
                print(scanner['response']['error'])
            else:
                print("\033[0;0mThere are \033[1;31m{}\033[0;0m domains using this mail server".format(scanner['response']['domain_count']))
                sleep(0.2)
                for key in scanner['response']['domains']:
                    if '<br><br' in key:
                        key=key.replace('<br><br>','')
                        print(key)
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def ns_lookup(domain):
    url="https://api.viewdns.info/reversens/?ns={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;39m",end='')
            scanner=get_request.json()
            if 'error' in scanner['response']:
                print(scanner['response']['error'])
            else:
                print("\033[0;0mThere are \033[1;31m{}\033[0;0m domains using this name server".format(scanner['response']['domain_count']))
                sleep(0.2)
                for key in scanner['response']['domains']:
                    print(key['domain'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def email_lookup(domain):
    url="https://api.viewdns.info/freeemail/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;39m",end='')
            scanner=get_request.json()
            print(scanner['response']['result'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def traceroute(domain):
    url="https://api.viewdns.info/traceroute/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;31mS.No.\t\t\tHostname\t\t\t\t    IP\t\t\trtt\033[1;39m")
            scanner = get_request.json()
            for key in scanner['response']['hops']:
                print(key['number'],end='')
                print("\t\t",key['hostname'],end='')
                print("\t\t",key['ip'],end='')
                print("\t\t",key['rtt'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))


def ip_locate(ip):
    url="https://api.viewdns.info/iplocation/?ip={}&apikey={}&output=json".format(ip,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            print("\033[1;39m",end='')
            locate=get_request.json()
            print("city              {}".format(locate['response']['city']))
            print("zipcode           {}".format(locate['response']['zipcode']))
            print("region_code       {}".format(locate['response']['region_code']))
            print("country_code      {}".format(locate['response']['country_code']))
            print("latitude          {}".format(locate['response']['latitude']))
            print("longitude         {}".format(locate['response']['longitude']))
            print("gmt_offset        {}".format(locate['response']['gmt_offset']))
            print("dst_offset        {}".format(locate['response']['dst_offset']))
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def iphistory(domain):
    hhistory=[]
    url="https://api.viewdns.info/iphistory/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            history=get_request.json()
            print("\033[1;31m\tIP\t\t\tLOCATION\t\t OWNER\t\t\tLAST_SEEN\033[1;39m")
            for key in history['response']['records']:
                print(key['ip'],end='')
                print("\t\t",key['location'],end='')
                print("\t\t",key['owner'],end='')
                print("\t\t",key['lastseen'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def google_page_rank(domain):
    print("\033[0;0mGOOGLE page rank for \033[1;31m{}".format(domain))
    sleep(0.2)
    url="https://api.viewdns.info/pagerank/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            page_rank=get_request.json()
            print("\033[1;39m",end='')
            if not page_rank['response']['pagerank']:
                print("NO response")
            else:
                print(page_rank['response']['pagerank'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def http_header(domain):
    print("\033[0;0mHTTP Header Records for \033[1;31m{}".format(domain))
    sleep(0.2)
    url="https://api.viewdns.info/httpheaders/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            header=get_request.json()
            print("  NAME\t\t\tVALUE\033[1;39m")
            for key in header['response']['headers']:
                print(key['name'],end='')
                if len(key['name'])<8:
                    print("\t\t\t",key['value'])
                else:
                    print("\t\t",key['value'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))


def dns_record(domain):
    print("\033[0;0mDNS Records for \033[1;31m{}".format(domain))
    sleep(0.2)
    url_list=["https://api.viewdns.info/dnsrecord/?domain={}&recordtype=A&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=SOA&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=NS&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=AAAA&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=CAA&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=TXT&apikey={}&output=json","https://api.viewdns.info/dnsrecord/?domain={}&recordtype=MX&apikey={}&output=json"]
    print("\033[1;31m  NAME			 TTL\t\tCLASS\t\tTYPE\t\t\tDATA")
    for uri in url_list:
        url=uri.format(domain,api_key())
        get_request=requests.get(url)
        if get_request.text=='Query limit reached for the supplied API key.':
            print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
        else:
            try:
                dns_record=get_request.json()
                print("\033[1;39m",end='')
                for key in dns_record['response']['records']:
                    print(key['name'],end='')
                    print("\t\t",key['ttl'],end='')
                    print("\t\t",key['class'],end='')
                    print("\t\t",key['type'],end='')
                    print("\t\t",key['data'])
            except:
                print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))

def dns_propagation(domain):
    print("\033[0;0mDNS Propagation results for \033[1;31m{}".format(domain))
    sleep(0.2)
    url="https://api.viewdns.info/propagation/?domain={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        try:
            propagation=get_request.json()
            print(" \033[1;37m Location\t\t\tStatus")
            print("\033[1;39m",end='')
            for key in propagation['response']['server']:
                print(key['location'],end='')
                if len(key['location'])<16:
                    print("\t\t\t",key['resultstatus'])
                else:
                    print("\t\t",key['resultstatus'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))
                    
def reverse_dns_lookup(domain):
    url="https://api.viewdns.info/reversedns/?ip={}&apikey={}&output=json".format(domain,api_key())
    get_request=requests.get(url)
    if get_request.text=='Query limit reached for the supplied API key.':
        print("\033[1;31mQuery limit reached for the supplied API key.\033[0;0m")
    else:
        print("\033[1;39m",end='')
        try:
            DNSLookup=get_request.json()
            print(DNSLookup['response']['rdns'])
        except:
            print("\033[1;31m Invalid API key '\033[1;32m{}\033[1;31m'".format(api_key()))
        

def root():
    k=7
    banner(k)
    #check_file()
    condition=True
    f='first'
    while condition:
        try:
            user = input("\033[1;31mDNS-INFO\033[1;34m>>\033[1;37m")
            if not user:
                pass
            elif user == 'help':
                Main_Menu()
            elif user == 'about':
                about()
            elif 'api' in user:
                path='/usr/share/DNSInfo_IHA/APIkey'
                if 'add api' in user:
                    user = user.replace('add api ','')
                    key=open(path,'w')
                    key.write(user)
                    key.close()
                elif user == 'api':
                    key=open(path,'r')
                    k=key.read()
                    if not k:
                        print("NO API Key")
                    else:
                        print(k)
            elif user == 'create':
                print("Create an accout on https://viewdns.info/api/#register\nconfirm your mail using gmail\n\nthen click on 'EXISTIN USER LOGIN' button at https://viewdns.info/api/# and login\ncopy your API Key\nand run command add api <Your API Key>\n\nin free accout we have 250 requests for trial\n\n")
            elif user == '1':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    reverse_dns_lookup(ip)
            elif user == '2':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    dns_propagation(domain)
            elif user == '3':
                domain=input("\033[1;33mEnter Domain:\033[1;31m")
                ip=check_domain_work(domain)
                if ip:
                    dns_record(domain)
            elif user == '4':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    http_header(ip)
            elif user == '5':
                domain=input("\033[1;33mEnter Domain:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    google_page_rank(domain)
            elif user == '6':
                domain=input("\033[1;33mEnter Domain:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    iphistory(domain)
            elif user == '7':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    traceroute(ip)
            elif user == '8':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    ip_locate(ip)
            elif user == '9':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    port_scanner(ip)
            elif user == '10':
                domain=input("\033[1;33mEnter Domain:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    mx_lookup(domain)
            elif user == '11':
                domain=input("\033[1;33mEnter Domain:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    ns_lookup(domain)
            elif user == '12':
                domain=input("\033[1;33mEnter Domain:\033[1;37m")
                ip=check_domain_work(domain)
                if ip:
                    email_lookup(domain)
            elif user == '13':
                domain=input("\033[1;33mEnter Domain/IP:\033[1;31m")
                ip=check_domain_work(domain)
                if ip:
                    ip_lookup(ip)
            elif user == 'clear':
                os.system("clear")
                k=randrange(9)
                banner(k)
            elif user == 'exit' or user == 'quit':
                print("\033[1;32m Exiting....")
                condition=False
                command="kill {}".format(current_pid)
                os.system(command)
            else:
                print("\033[1;39minvalid command \033[1;36m: {}".format(user))
                if f == 'first':
                    print("\033[1;39mtype '\033[1;36mhelp\033[1;39m' for more information")
                    f = 'chang'

        except KeyboardInterrupt:
            print("\n", end='')


root()

