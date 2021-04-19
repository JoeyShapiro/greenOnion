import smtplib # for emailing proper people
from email.message import EmailMessage
from scapy.all import * # for sniffing the net
import json # for the rules

sender = 'project@localhost'

banner = open('banner')
f = open('rules.json', 'r') # json of the rules
flog = open('logs.pcap', 'ab') # file of logs of important locations

# bad locations, IPs of them and where to email if sent
rules = json.loads(f.read())

# load into list of IPs
def check_bad(dst):
    try: # essentially if bad
        email = rules[dst]
        return email
    except: # essentially if not bad
        return

# emailing people
def notifyEmail(to, ip):
    #open file for email
    #who to send
    #send
    # email to be sent
    message = 'Attention, ' + to + ' , someone has gone to the bad IP: ' + ip + ' , and it requires your futher attention. This information has been logged in the file.'
    print(message)
    try:
        smtpObj = smtplib.SMTP('localhost')
        header = 'To:' + to + '\n' + 'From:' + sender + '\n' + 'Subject:notice \n'
        message = header + message
        smtpObj.sendmail(sender, to, message)
        print('sent notice to proper recipient')
    except SMTPException:
        print('ERROR: Email')

# what to do with each packet
def print_pkt(pkt):
    # if ip is in list then notify proper
    try:
        destination = pkt['IP'].dst # IP destination
        # make list just give website and look for each of that
        recipient = check_bad(destination)
        if(recipient != None):
            arr = recipient.split(',')
            site = arr[0]
            to = arr[1]
            notifyEmail(to, site)
            wrpcap(flog, pkt, append=True) #flog.write(raw(pkt)) # figure out
    except: # if the pkt is just stupid or something
        pass

print(banner.read())
print("Sniffing the network for bad traffic")
sniff(filter="", prn=print_pkt)