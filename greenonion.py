import smtplib # for emailing proper people
from email.message import EmailMessage
from scapy.all import * # for sniffing the net
import json # for the rules

f = open('rules.json', 'r') # json of the rules
flog = open('logs', 'a') # file of logs of important locations

# bad locations, IPs of them and where to email if sent
rules = json.loads(f)

# load into list of IPs

# emailing people
def notifyEmail(to):
    #open file for email
    #who to send
    #send

# what to do with each packet
def print_pkt(pkt):
    # if ip is in list then notify proper

sniff(filter="", prn=print_pkt)