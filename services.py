#!/usr/bin/env python3
#####################################################################
#                                                                   #
# The purpose of this code is to extract the ClearPass Policy       # 
# Manager Service configuration details account.                    #
# This uses the legacy ClearPass XML interface - the configuration  #
# information is not exposed via the RESTful API as ot ClearPass    #
# v6.9.5.                                                           #
# WARNING: This code has only had minimal testing on v6.9 code,     #
# though I will expect it to work on v6.8 and v6.7.                 #
#                                                                   #
# Known Limitations                                                 #
# Enforcement Profiles: AOS DUR using Standard forms do not work,   #
# AOS DUR usuing Advanced seems to but not the bandwidth/QOS        #
# AuthSources: Only AD and RADIUS Server tested                     #
# Posture Compliance: Only reports the posture compliance name      #
# Local Users: These are currently not been processed               #
#                                                                   #
# Author: Derin Mellor                                              #
# Date: 21st April 2021                                             #
# Version: 0.2                                                      #
# Contact: derin.mellor@blueskysystems.com                          #
#                                                                   #
# Changes                                                           #
# 0.1 First version                                                 #
# 0.2 Due to problems on macOS moved from pycurl module to requests #
#     module. Significant enhancements on pdf output.               #
#                                                                   #
#                                                                   #
# Usage: services.py -D -h hostname/IP -u username -p password      #
# Where:                                                            #
#   -D  debug                                                       #
#   -h  hostname/IP - note validation of certificate or IP will     #
#       work                                                        #
#   -u  username - typically use the generic apiadmin account       #
#                                                                   #
# Running Challenges                                                #
# The two challenging python modules that need loading at pycurl    #
# and lxml.                                                         #
# macOS:                                                            #
#   1) macOS defaults to python2 - this is written in python3!      #
#   2) It defaults to using the LibreSSL libraries whereas pycurl   #
#       expects openssl libraries. Search the internet for          #
#       ssl-backend-error-when-using-openssl                        #
#   3) lxml causes challenges - look at                             #
#       https://lxml.de/installation.html                           #
#                                                                   #
# When the code starts running it uses the XML API to extract the   #
# configuration information and place these into the appropriate    #
# objects. Once this is complete it will output the information.    #
# Currently all the information is output on the console.           #
#                                                                   #
# WARNING: If using on a Linux environment you might experience the #
# error:                                                            #
#       ./services.py -h clearpass.hpearubademo.com                 #
#       env: python3\r: No such file or directory                   #
# This is most likely caused due to being developed on a Windows    #
# platform that within the file format uses \n\r at the end-of-line.#
# Linux format just uses a \r. If you experience this error convert #
# it to a Linux format using the "dos2unix" command:                #       
#       dos2unix services.py services.py                            #
#                                                                   #
#####################################################################
import sys
#import pycurl
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import io
import xml.etree.ElementTree as ET
from fpdf import FPDF
from datetime import datetime, timedelta
from getpass import getpass

DEBUG=False
EXPIRE='2021-07-28'

HOSTNAME=''
USERNAME=''
PASSWORD=''
#HOSTNAME='cppm.hpearubademo.com'
#USERNAME='apiadmin'
#PASSWORD='aruba123'
#pdf=0
H=8
h=6


AUTH_METHODS={}
AUTH_METHODS_SORTED=[]
AUTH_SOURCES={}
AUTH_SOURCES_SORTED=[]
NAD_CLIENTS={}
NAD_CLIENTS_SORTED=[]
NAD_GROUPS={}
NAD_GROUPS_SORTED=[]
PROXIES={}
PROXIES_SORTED=[]
ROLES={}
ROLES_SORTED=[]
ROLE_MAPPINGS={}
ROLE_MAPPINGS_SORTED=[]
ENF_POLICIES={}
ENF_POLICIES_SORTED=[]
PROFILES={}
PROFILES_SORTED=[]
SERVICES={}
SERVICES_SORTED=[]

class Nad(object):
    """Network Access Device"""
    total=0

    @staticmethod
    def total():
        print('Total number of Network Access Devices=', Nad.total)

    def referenced():
        print('Total number of referenced=', Nad.referenced)

    def used():
        print('Total number of referenced=', Nad.used)

    def __init__(self, name, description, coaPort, coaCapable, vendor, tacacsSecret, radiusSecret, ip):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
        self.coaPort=coaPort
        self.coaCapable=coaCapable
        self.vendor=vendor
        self.tacacsSecret=tacacsSecret
        self.radiusSecret=radiusSecret
        self.ip=ip
        self.attribDict={}
        self.snmpReadCommunity=''
        self.snmpReadVersion=0
        self.snmpReadUser=''
        self.snmpReadSecurityLevel=''
        self.snmpReadAuthProtocol=''
        self.snmpReadAuthKey=''
        self.snmpReadPrivProtocol=''
        self.snmpReadPrivKey=''
        self.snmpWriteCommunity=''
        self.snmpWriteVersion=0
        self.snmpWriteUser=''
        self.snmpWriteSecurityLevel=''
        self.snmpWriteAuthProtocol=''
        self.snmpWriteAuthKey=''
        self.snmpWritePrivProtocol=''
        self.snmpWritePrivKey=''
        self.snmpReadArpInfo=False
        self.onConnectEnforcement=False
        self.onConnectPorts=''
        self.zone=''
        self.defaultVlan=0
        self.radEnabled=False
        self.radSrcOverrideIP=''
        self.radSANregex=''
        self.radCNregex=''
        self.radValCert=''
        self.radIssuer=''
        self.radSerialNo=''
#        Nad.total+=1

    def output(self):

        nas=self

        if DEBUG:
            print('Entering nad.output',nas.name)

        try: 
            print(nas.name)
            print('\tIP:', nas.ip)
            if nas.description:
                print('\tDescription:', nas.description)
            print('\tVendor:',nas.vendor)
            if nas.radiusSecret:
#                print('\tRADIUS secret:', nas.radiusSecret)
                print('\tRADIUS secret: xxxxxx')
            if nas.coaCapable:
                print('\tCoA Capable:', nas.coaCapable)
                print('\t\tCoA Port:', nas.coaPort)
            if nas.radEnabled:
                print('\tRadsec Enabled')
                print('\t\tRadsec Source Override IP:', nas.radSrcOverrideIP)
                if nas.radSANregex:
                    print('\t\tRadsec SAN Regex:', nas.radSANregex)
                if nas.radCNregex:
                    print('\t\tRadsec CN Regex:', nas.radCNregex)
                if nas.radValCert:
                    print('\t\tRadsec Validate Certificate:', nas.radValCert)
                if nas.radIssuer:
                    print('\t\tRadsec Issuer:', nas.radIssuer)
                if nas.radSerialNo:
                    print('\t\tRadsec Serial Number:', nas.radSerialNo)
            print('\tZone:', nas.zone)
            print('\tDefault VLAN:', nas.defaultVlan)
            if nas.tacacsSecret:
#                print('\tTACACS secret:', nas.tacacsSecret)
                print('\tTACACS secret: xxxxxx')
            print('\tSNMP Read ARP table:', nas.snmpReadArpInfo)
            if nas.snmpReadVersion=='V1' or nas.snmpReadVersion=='V2C':
                print('\tSNMP Read')
                print('\t\tVersion:', nas.snmpReadVersion)
#                print('\t\tCommunity:', nas.snmpReadCommunityString)
                print('\t\tCommunity: xxxxxx')
            elif nas.snmpReadVersion=='V3':
                print('\tSNMP Read')
                print('\t\tVersion:', nas.snmpReadVersion)
                print('\t\tUsername:', nas.snmpReadUser)
                if nas.snmpReadSecurityLevel:
                    print('\t\tSecurity Level:', nas.snmpReadSecurityLevel)
                print('\t\tAuthentication Protocol:', nas.snmpReadAuthProtocol)
#                print('\t\tAuthentication Key:', nas.snmpReadAuthKey)
                print('\t\tAuthentication Key: xxxxxx')
                print('\t\tPrivilege Protocol:', nas.snmpReadPrivProtocol)
#                print('\t\tPrivilege Key:', nas.snmpReadPrivKey)
                print('\t\tPrivilege Key: xxxxxx')
            if nas.snmpWriteVersion=='V1' or nas.snmpWriteVersion=='V2C':
                print('\tSNMP Write')
                print('\t\tVersion:', nas.snmpWriteVersion)
#                print('\t\tCommunity:', nas.snmpWriteCommunityString)
                print('\t\tCommunity: xxxxxx')
            elif nas.snmpWriteVersion=='V3':
                print('\tSNMP Write')
                print('\t\tVersion:', nas.snmpWriteVersion)
                print('\t\tUsername:', nas.snmpWriteUser)
                if nas.snmpWriteSecurityLevel:
                    print('\t\tSecurity Level:', nas.snmpWriteSecurityLevel)
                print('\t\tAuthentication Protocol:', nas.snmpWriteAuthProtocol)
#                print('\t\tAuthentication Key:', nas.snmpWriteAuthKey)
                print('\t\tAuthentication Key: xxxxxx')
                print('\t\tPrivilege Protocol:', nas.snmpWritePrivProtocol)
#                print('\t\tPrivilege Key:', nas.snmpWritePrivKey)
                print('\t\tPrivilege Key: xxxxxx')
            if nas.onConnectEnforcement:
                print('\tonConnect Enabled')
                print('\t\tonConnect ports:', nas.onConnectPorts)
            if nas.attribDict:
                print('\tCustomer Attributes')
                for key, value in nas.attribDict.items():
                    print('\t\t',key,':',value)

        except Exception as e:
            print('Error nad.output: ',e)
            print(nas.attribDict.items())
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving nad.output',self.name)

            return 1

    
    def output_pdf(self):

        nas=self

        if DEBUG:
            print('Entering nad.output_pdf',nas.name)

        try: 
            pdf.ln(h)
            pdf.set_font("Arial", size = 11)
            pdf.cell(5, h, '', 0, 0, 'L')
            pdf.cell(0, h, nas.name, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'IP', 0, 0, 'L')
            pdf.cell(0, h, nas.ip, 0, 1, 'L')
            if nas.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, nas.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Vendor', 0, 0, 'L')
            pdf.cell(0, h, nas.vendor, 0, 1, 'L')
            if nas.radiusSecret:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'RADIUS Secret', 0, 0, 'L')
#                pdf.cell(0, h, nas.radiusSecret, 0, 1, 'L')
                pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            if nas.coaCapable:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'CoA Capable', 0, 0, 'L')
                pdf.cell(0, h, nas.coaCapable, 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'CoA Port', 0, 0, 'L')
                pdf.cell(0, h, nas.coaPort, 0, 1, 'L')
            if nas.radEnabled:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Radsec', 0, 0, 'L')
                pdf.cell(0, h, 'Enabled', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Radsec Source Override IP', 0, 0, 'L')
                pdf.cell(0, h, nas.radSrcOverrideIP, 0, 1, 'L')
                if nas.radSANregex:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Radsec SAN Regex', 0, 0, 'L')
                    pdf.cell(0, h, nas.radSANregex, 0, 1, 'L')
                if nas.radCNregex:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Radsec CN Regex', 0, 0, 'L')
                    pdf.cell(0, h, nas.radCNregex, 0, 1, 'L')
                if nas.radValCert:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Radsec Validate Certificate', 0, 0, 'L')
                    pdf.cell(0, h, nas.radValCert, 0, 1, 'L')
                if nas.radIssuer:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Radsec Issuer', 0, 0, 'L')
                    pdf.cell(0, h, nas.radIssuer, 0, 1, 'L')
                if nas.radSerialNo:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Radsec Serial Number', 0, 0, 'L')
                    pdf.cell(0, h, nas.radSerialNo, 0, 1, 'L')
            if nas.zone:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Zone', 0, 0, 'L')
                pdf.cell(0, h, nas.zone, 0, 1, 'L')
            if nas.defaultVlan:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Default VLAN', 0, 0, 'L')
                pdf.cell(0, h, str(nas.defaultVlan), 0, 1, 'L')
            if nas.tacacsSecret:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'TACACS secret', 0, 0, 'L')
#                pdf.cell(0, h, nas.tacacsSecret, 0, 1, 'L')
                pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            if nas.snmpReadArpInfo:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'SNMP Read ARP table', 0, 0, 'L')
                pdf.cell(0, h, 'True', 0, 1, 'L')
            if nas.snmpReadVersion=='V1' or nas.snmpReadVersion=='V2C':
                pdf.cell(10, h, '', 0, 0, 'L')
                string='SNMP Read'
                pdf.cell(60, h, 'SNMP Read', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Version', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpReadVersion, 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Community', 0, 0, 'L')
#                pdf.cell(0, h, nas.snmpReadCommunityString, 0, 1, 'L')
                pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            elif nas.snmpReadVersion=='V3':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'SNMP Read', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Version', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpReadVersion, 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Username', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpReadUser, 0, 1, 'L')
                if nas.snmpReadSecurityLevel:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Security Level', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpReadSecurityLevel, 0, 1, 'L')
                if nas.snmpReadAuthProtocol:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Authentication Protocol', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpReadAuthProtocol, 0, 1, 'L')
                if nas.snmpReadAuthKey:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Authentication Key', 0, 0, 'L')
#                    pdf.cell(0, h, nas.snmpReadAuthKey, 0, 1, 'L')
                    pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
                if nas.snmpReadPrivProtocol:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Privilege Protocol', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpReadPrivProtocol, 0, 1, 'L')
                if nas.snmpReadPrivKey:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Privilege Key', 0, 0, 'L')
#                    pdf.cell(0, h, nas.snmpReadPrivKey, 0, 1, 'L')
                    pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            if nas.snmpWriteVersion=='V1' or nas.snmpWriteVersion=='V2C':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'SNMP Write', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Version', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpWriteVersion, 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Community', 0, 0, 'L')
#                pdf.cell(0, h, nas.snmpWriteCommunityString, 0, 1, 'L')
                pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            elif nas.snmpWriteVersion=='V3':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'SNMP Write', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Version', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpWriteVersion, 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Username', 0, 0, 'L')
                pdf.cell(0, h, nas.snmpWriteUser, 0, 1, 'L')
                if nas.snmpWriteSecurityLevel:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Seucrity Level', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpWriteSecurityLevel, 0, 1, 'L')
                if nas.snmpWriteAuthProtocol:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Authentication Protocol', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpWriteAuthProtocol, 0, 1, 'L')
                if nas.snmpWriteAuthKey:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Authentication Key', 0, 0, 'L')
#                    pdf.cell(0, h, nas.snmpWriteAuthKey, 0, 1, 'L')
                    pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
                if nas.snmpWritePrivKey:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Privilege Protocol', 0, 0, 'L')
                    pdf.cell(0, h, nas.snmpWritePrivProtocol, 0, 1, 'L')
                if nas.snmpWritePrivKey:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Privilege Key', 0, 0, 'L')
#                    pdf.cell(0, h, nas.snmpWritePrivKey, 0, 1, 'L')
                    pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
            if nas.onConnectEnforcement:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'onConnect', 0, 0, 'L')
                pdf.cell(0, h, 'Enabled', 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'onConnect ports', 0, 0, 'L')
                pdf.cell(0, h, nas.onConnectPorts, 0, 1, 'L')
            if nas.attribDict:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Custom Attributes', 0, 1, 'L')
                for key, value in nas.attribDict.items():
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, key, 0, 0, 'L')
                    pdf.cell(0, h, value, 0, 1, 'L')

        except Exception as e:
            print('Error nad.output_pdf: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving nad.output_pdf',self.name)

            return 1


class Auth_Method(object):
    """Auth_Method"""
    total=0

    @staticmethod
    def total():
        print('Total number of Auth_Method =', Auth_Method.total)

    def referenced():
        print('Total number of referenced =', Auth_Method.referenced)

    def used():
        print('Total number of referenced =', Auth_Method.used)

    def __init__(self, name, description, method):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
        self.method=method
        self.outer={}
        self.inner={}
#        Auth_Method.total+=1


    def output(self):
        if DEBUG:
            print('Entering Auth_Method.output',self.name)

        try: 
            print(self.name)
            if self.description:
                print('\tDescription:',self.description)
            print('\tMethod:',self.method)
            for key, value in self.outer.items():
                print('\t\t',key,':',value)
#            print('self.inner=',self.inner[self.name])
            if self.name in self.inner:
                print('\tInner Methods')
                for key, value in self.inner.items():
                    for i in value:
                        print('\t\t',i)
    
        except Exception as e:
            print('Error Auth_Method.output: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Auth_Method.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Auth_Method.output_pdf',self.name)

        try: 
            pdf.set_font("Arial", size = 11)
            pdf.cell(0, h, self.name, 0, 1, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Method', 0, 0, 'L')
            pdf.cell(0, h, self.method, 0, 1, 'L')
            for key, value in self.outer.items():
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, key, 0, 0, 'L')
                pdf.cell(0, h, value, 0, 1, 'L')
#            string='self.inner=',self.inner[self.name])
            if self.name in self.inner:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Inner Methods', 0, 1, 'L')
                for key, value in self.inner.items():
                    for i in value:
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(0, h, i, 0, 1, 'L')
    
        except Exception as e:
            print('Error Auth_Method.output_pdf: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving Auth_Method.output_pdf',self.name)

            return 1


def ad_auths_output(src):

    if DEBUG:
        print('Entering ad_auths_output',src)

    print('Hostname: ',src['server'],sep='')
    print('\t\tConnection Security: ',end='')
    if src['connect_type']=='none':
        print('None')
    elif src['connect_type']=='start_tls':
        print('StartTLS')
    elif src['connect_type']=='ssl':
        print('AD over SSL')
    else:
        print('What is this?',src['connect_type'])
    print('\t\tPort: ',src['port'])
    print('\t\tVerify Server Certificate: ',src['verify_peer'])
    print('\t\tBind DN: ',src['identity'])
#    print('\t\tBind Password: ',src['password'])
    print('\t\tBind Password: xxxxxx')
    print('\t\tNetBIOS Domain Name: ',src['netbios_name'])
    print('\t\tBase DN: ',src['basedn'])
    print('\t\tSearch Scope: ',end='')
    if src['scope_type']=='sub':
        print('SubTree Search')
    elif src['scope_type']=='base':
        print('Base Object Search')
    elif src['scope_type']=='one':
        print('One Level Search')
    else:
        print(src['scope_type'])
    print('\t\tLDAP Referrals: ',src['allow_referral'])
    print('\t\tBind User: ',end='')
    if 'authentication_source' in i:
        if src['authentication_source']=='false':
            print('False')
        else:
            print('True')
    else:
        print('True')
    print('\t\tUser Certificate: ',src['certificate_attr'])
    print('\t\tAlways use NetBIOS name: ', src['override_domain_name'])
    print('\t\tSpecial Character Handling for Query: ',end='')
    if 'replace_special_char' in i:
        if src['replace_special_char']=='false':
            print('False')
        else:
            print('True')
    else:
        print('True')

    if DEBUG:
        print('Leaving ad_auths_output',src)
    return

    
def ad_auths_output_pdf(src):
    if DEBUG:
        print('Entering ad_auths_output_pdf',src)

    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Hostname', 0, 0, 'L')
    pdf.cell(60, h, src['server'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Connection Security', 0, 0, 'L')
    if src['connect_type']=='none':
        string='None'
    elif src['connect_type']=='start_tls':
        string='StartTLS'
    elif src['connect_type']=='ssl':
        string='AD over SSL'
    else:
        string='What is this? '+src['connect_type']
    pdf.cell(60, h, string, 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Port', 0, 0, 'L')
    pdf.cell(60, h, src['port'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Verify Server Certificate', 0, 0, 'L')
    pdf.cell(60, h, src['verify_peer'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Bind DN', 0, 0, 'L')
    pdf.cell(60, h, src['identity'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Bind Password', 0, 0, 'L')
#    pdf.cell(60, h, src['password'], 0, 1, 'L')
    pdf.cell(60, h, 'xxxxxx', 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'NetBIOS Domain Name', 0, 0, 'L')
    pdf.cell(60, h, src['netbios_name'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Base DN', 0, 0, 'L')
    pdf.cell(60, h, src['basedn'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    string='Search Scope: '
    pdf.cell(60, h, 'Search Scope', 0, 0, 'L')
    if src['scope_type']=='sub':
        string='SubTree Search'
    elif src['scope_type']=='base':
        string='Base Object Search'
    elif src['scope_type']=='one':
        string='One Level Search'
    else:
        string=src['scope_type']
    pdf.cell(60, h, string, 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'LDAP Referrals', 0, 0, 'L')
    pdf.cell(60, h, src['allow_referral'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Bind User', 0, 0, 'L')
    if 'authentication_source' in i:
        if src['authentication_source']=='false':
            string='False'
        else:
            string='True'
    else:
        string='True'
    pdf.cell(60, h, string, 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'User Certificate', 0, 0, 'L')
    pdf.cell(60, h, src['certificate_attr'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Always use NetBIOS name', 0, 0, 'L')
    pdf.cell(60, h, src['override_domain_name'], 0, 1, 'L')
    pdf.cell(20, h, '', 0, 0, 'L')
    pdf.cell(60, h, 'Special Char Handling for Query', 0, 0, 'L')
    if 'replace_special_char' in i:
        if src['replace_special_char']=='false':
            string='False'
        else:
            string='True'
    else:
        string='True'
    pdf.cell(60, h, string, 0, 1, 'L')

    if DEBUG:
        print('Leaving ad_auths_output_pdf',src)
    return

    
class Auth_Src(object):
    """Authentication Sources"""
    total=0

    @staticmethod
    def total():
        print('Total number of Authentication Sources=', Auth_Src.total)

    def referenced():
        print('Total number of referenced=', Auth_Src.referenced)

    def used():
        print('Total number of referenced=', Auth_Src.used)

    def __init__(self, name, description, isAuthzSrc, authType):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
        self.isAuthzSrc=isAuthzSrc
        self.authType=authType
        self.nvPairDict={}
        self.filterQueryDict={}
        self.filterAttribDict={}    # This is a Filter{name}Attribute{name}[values]
        self.backup=[]
        self.preProxy=[]
        self.postProxy=[]
#        Auth_Src.total+=1

    def output(self):
        authsrc=self
        if DEBUG:
            print('Entering Auth_Src.output',self.name)

        try: 
            print('Authentication Source: ',authsrc.name)
            if authsrc.description:
                print('\tDescription:', authsrc.description)
            print('\tType: ',authsrc.authType)
            print('\tAuthorization Source: ',authsrc.isAuthzSrc)
            print('\t\tServer Timeout: ',authsrc.nvPairDict['timeout'])
            if 'cache_timeout' in authsrc.nvPairDict:
                print('\t\tCache Timeout: ',authsrc.nvPairDict['cache_timeout'])
            if authsrc.authType=='AD':
                if authsrc.nvPairDict:
                    print('\tPrimary ',end='')
                    ad_auths_output(authsrc.nvPairDict)
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        print('\tBackup #',c,' ',sep='',end='')
                        ad_auths_output(i)
                        c+=1
            elif authsrc.authType=='RadiusServer':
                print('\tPrimary Server Name:',authsrc.nvPairDict['authhost'])
                print('\t\tProtocol:',authsrc.nvPairDict['protocol'])
                print('\t\tPort:',authsrc.nvPairDict['authport'])
#                print('\t\tSecret:',authsrc.nvPairDict['secret'])
                print('\t\tSecret: xxxxxx')
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        print('\tBackup #',c,' Server Name:',authsrc.nvPairDict['authhost'],sep='')
                        print('\t\tProtocol:',authsrc.nvPairDict['protocol'])
                        print('\t\tPort:',authsrc.nvPairDict['authport'])
#                        print('\t\tSecret:',authsrc.nvPairDict['secret'])
                        print('\t\tSecret: xxxxxx')
                        c+=1
            elif authsrc.authType=='Sql':
                if authsrc.nvPairDict:
                    print('\tPrimary ',end='')
                    print(authsrc.nvPairDict)
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        print('\tBackup #',c,' ',sep='',end='')
                        print(i)
                        c+=1
            else:
                print('\tPrimary ',end='')
                for key in authsrc.nvPairDict:
                    if key=='timeout':
                        continue
                    if key=='cache_timeout':
                        continue
                    print('\t\t',key,':',authsrc.nvPairDict[key])
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        print('\tBackup #',c,' ',sep='',end='')
                        for key in i:
                            print('\t\t',key,':',i[key])
                        c+=1

            if authsrc.filterQueryDict:
                print('\tFilters')
                for key, value in authsrc.filterQueryDict.items():
                    print('\t\t',key,': filter=',value,sep='')
                    i=0
                    if key not in authsrc.filterAttribDict:
                        continue
                    attributes=authsrc.filterAttribDict[key]
                    print('\t\t\tLDAP Attrib Map\tCPPM Alias\tDataType\tRole/Attrib')
                    for key2, value2 in attributes.items():
                        print('\t\t\t',key2,'\t',value2[0],'\t',value2[1],'\t',value2[2],sep='')
            if authsrc.preProxy:
#                print('preProxy=',authsrc.preProxy)
                print('\tPreProxy RADIUS Attributes')
                for i in authsrc.preProxy:
                    if i['operator']=='1':
                        label='Add '
                    elif i['operator']=='3':
                        label='Delete '
                    else:
                        label=i['operator']+' '
                    if 'attrValue' in i:
                        print('\t\t',label,i['vendor'],':',i['attrName'],' = ', i['attrValue'], sep='')
                    else:
                        print('\t\t',label,i['vendor'],':',i['attrName'], sep='')
            if authsrc.postProxy:
#                print('postProxy=',authsrc.postProxy)
                print('\tPostProxy RADIUS Attributes')
                for i in authsrc.postProxy:
                    if 'attrValue' in i:
                        print('\t\tAdd ',i['vendor'],':',i['attrName'],'=', i['attrValue'], sep='')
                    else:
                        print('\t\tAdd ',i['vendor'],':',i['attrName'], sep='')

        except Exception as e:
            print('Error Auth_Src.output: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving Auth_Src.output',self.name)

            return 1


    def output_pdf(self):
        authsrc=self
        if DEBUG:
            print('Entering Auth_Src.output_pdf',self.name)

        try: 
            pdf.ln(h)
            pdf.cell(60, h, 'Authentication Source', 0, 0, 'L')
            pdf.cell(0, h, authsrc.name, 0, 1, 'L')
            if authsrc.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, authsrc.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Type', 0, 0, 'L')
            pdf.cell(0, h, authsrc.authType, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Authorization Source', 0, 0, 'L')
            pdf.cell(0, h, authsrc.isAuthzSrc, 0, 1, 'L')
            pdf.cell(20, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Server Timeout', 0, 0, 'L')
            pdf.cell(0, h, authsrc.nvPairDict['timeout'], 0, 1, 'L')
            if 'cache_timeout' in authsrc.nvPairDict:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Cache Timeout', 0, 0, 'L')
                pdf.cell(0, h, authsrc.nvPairDict['cache_timeout'], 0, 1, 'L')
            if authsrc.authType=='AD':
                if authsrc.nvPairDict:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(0, h, 'Primary', 0, 1, 'L')
                    ad_auths_output_pdf(authsrc.nvPairDict)
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        pdf.cell(10, h, '', 0, 0, 'L')
                        string='Backup #'+str(c)
                        pdf.cell(0, h, string, 0, 1, 'L')
                        ad_auths_output_pdf(i)
                        c+=1
            elif authsrc.authType=='RadiusServer':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Primary Server Name', 0, 0, 'L')
                pdf.cell(0, h, authsrc.nvPairDict['authhost'], 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Protocol', 0, 0, 'L')
                pdf.cell(0, h, authsrc.nvPairDict['protocol'], 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Port', 0, 0, 'L')
                pdf.cell(0, h, authsrc.nvPairDict['authport'], 0, 1, 'L')
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Secret', 0, 0, 'L')
#                pdf.cell(0, h, authsrc.nvPairDict['secret'], 0, 1, 'L')
                pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        pdf.cell(10, h, '', 0, 0, 'L')
                        string='Backup #'+str(c)+' Server Name: '
                        pdf.cell(60, h, string, 0, 0, 'L')
                        pdf.cell(0, h, authsrc.nvPairDict['authhost'], 0, 1, 'L')
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(60, h, 'Protocol', 0, 0, 'L')
                        pdf.cell(0, h, authsrc.nvPairDict['protocol'], 0, 1, 'L')
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(60, h, 'Port', 0, 0, 'L')
                        pdf.cell(0, h, authsrc.nvPairDict['authport'], 0, 1, 'L')
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(60, h, 'Secret', 0, 0, 'L')
#                        pdf.cell(0, h, authsrc.nvPairDict['secret'], 0, 1, 'L')
                        pdf.cell(0, h, 'xxxxxx', 0, 1, 'L')
                        c+=1
            else:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Primary', 0, 1, 'L')
                for key in authsrc.nvPairDict:
                    if key=='timeout':
                        continue
                    if key=='cache_timeout':
                        continue
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(60, h, key, 0, 0, 'L')
                    pdf.cell(0, h, authsrc.nvPairDict[key], 0, 1, 'L')
                if authsrc.backup:
                    c=1
                    for i in authsrc.backup:
                        pdf.cell(10, h, '', 0, 0, 'L')
                        string='Backup #'+str(c)
                        pdf.cell(0, h, string, 0, 1, 'L')
                        for key in i:
                            pdf.cell(20, h, '', 0, 0, 'L')
                            pdf.cell(60, h, key, 0, 0, 'L')
                            pdf.cell(0, h, i[key], 0, 1, 'L')
                        c+=1

            if authsrc.filterQueryDict:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Filters', 0, 1, 'L')
                for key, value in authsrc.filterQueryDict.items():
                    pdf.cell(20, h, '', 0, 0, 'L')
                    string=key+': filter='+value
                    if len(string)>180:
                        pdf.multi_cell(0,h,string, 'L')
                    else:
                        pdf.cell(0, h, string, 0, 1, 'L')
                    i=0
                    if key not in authsrc.filterAttribDict:
                        continue
                    attributes=authsrc.filterAttribDict[key]
                    pdf.cell(30, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'LDAP Attrib Map', 0, 0, 'L')
                    pdf.cell(50, h, 'CPPM Alias', 0, 0, 'L')
                    pdf.cell(40, h, 'Data Type', 0, 0, 'L')
                    pdf.cell(40, h, 'Role/Attribute', 0, 1, 'L')
                    for key2, value2 in attributes.items():
                        pdf.cell(30, h, '', 0, 0, 'L')
                        pdf.cell(60, h, key2, 0, 0, 'L')
                        pdf.cell(50, h, value2[0], 0, 0, 'L')
                        pdf.cell(40, h, value2[1], 0, 0, 'L')
                        pdf.cell(40, h, value2[2], 0, 1, 'L')
#                        string='\t\t\t'+key2+'\t'+value2[0]+'\t'+value2[1]+'\t'+value2[2]
            if authsrc.preProxy:
#                string='preProxy='+authsrc.preProxy
                pdf.cell(10, h, '', 0, 0, 'L')
                string='PreProxy RADIUS Attributes'
                pdf.cell(0, h, string, 0, 1, 'L')
                for i in authsrc.preProxy:
                    if i['operator']=='1':
                        label='Add '
                    elif i['operator']=='3':
                        label='Delete '
                    else:
                        label=i['operator']+' '
                    pdf.cell(20, h, '', 0, 0, 'L')
                    if 'attrValue' in i:
                        string=label+i['vendor']+':'+i['attrName']+' = '+i['attrValue']
                        pdf.cell(0, h, string, 0, 1, 'L')
                    else:
                        string=label+i['vendor']+':'+i['attrName']
                        pdf.cell(0, h, string, 0, 1, 'L')
            if authsrc.postProxy:
#                string='postProxy='+authsrc.postProxy
                pdf.cell(10, h, '', 0, 0, 'L')
                string='PostProxy RADIUS Attributes'
                pdf.cell(0, h, string, 0, 1, 'L')
                for i in authsrc.postProxy:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    if 'attrValue' in i:
                        string='Add '+i['vendor']+':'+i['attrName']+'='+i['attrValue']
                        pdf.cell(0, h, string, 0, 1, 'L')
                    else:
                        string='Add '+i['vendor'],':'+i['attrName']
                        pdf.cell(0, h, string, 0, 1, 'L')

        except Exception as e:
            print('Error Auth_Src.output_pdf: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Auth_Src.output_pdf',self.name)

            return 1


class Role(object):
    """Role"""
    total=0

    @staticmethod
    def total():
        print('Total number of Roles=', Role.total)

    def referenced():
        print('Total number of referenced=', Role.referenced)

    def used():
        print('Total number of referenced=', Role.used)

    def __init__(self, name, description):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
#        Role.total+=1


    def output(self):
        if DEBUG:
            print('Entering Role.output',self.name)

        try: 
            print('\t',self.name,end='')
            if self.description:
                print('\tDescription:',self.description,end='')

    
        except Exception as e:
            print('Error Role.output: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving Role.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Role.output_pdf',self.name)

        try: 
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, self.name, 0, 0, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')

    
        except Exception as e:
            print('Error Role.output_pdf: ',e)
            return 0
    
        finally:
            pdf.ln(h)
            if DEBUG:
                print('Leaving Role.output_pdf',self.name)

            return 1


class NadGroup(object):
    """NAD Group"""
    total=0

    @staticmethod
    def total():
        print('Total number of NAD Group=', nadGroup.total)

    def referenced():
        print('Total number of referenced=', nadGroup.referenced)

    def used():
        print('Total number of referenced=', nadGroup.used)

    def __init__(self, name, description,members,membersFormat):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
        self.members=members
        self.membersFormat=membersFormat
#        nadGroup.total+=1


    def output(self):
        if DEBUG:
            print('Entering nadGroup.output',self.name)

        try: 
            print(self.name,end='')
            if self.description:
                print('\tDescription:',self.description,end='')
            print()
            print('\tFormat:',self.membersFormat)
            print('\tMembers:',self.members)

    
        except Exception as e:
            print('Error nadGroup.output: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving nadGroup.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering nadGroup.output_pdf',self.name)

        try: 
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, self.name, 0, 0, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            pdf.cell(20, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Format', 0, 0, 'L')
            pdf.cell(0, h, self.membersFormat, 0, 1, 'L')
            pdf.cell(20, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Memebers', 0, 0, 'L')
            pdf.cell(0, h, self.members, 0, 1, 'L')

    
        except Exception as e:
            print('Error nadGroup.output_pdf: ',e)
            return 0
    
        finally:
            pdf.ln(h)
            if DEBUG:
                print('Leaving andGroup.output',self.name)

            return 1


class Role_Mapping(object):
    """Role Mapping"""
    total=0

    @staticmethod
    def total():
        print('Total number of Role Mapping=', Role_Mapping.total)

    def referenced():
        print('Total number of referenced=', Role_Mapping.referenced)

    def used():
        print('Total number of referenced=', Role_Mapping.used)

    def __init__(self, name):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=''
        self.dfltRole=''
        self.ruleCombAlgo=''
        self.condition=[]
        self.result=[]
#        Role_Mapping.total+=1


    def output(self):
        if DEBUG:
            print('Entering Role_Mapping.output',self.name)

        try: 
            if self.description:
                print('\tDescription:',self.description)
            print('\tDefault Role:',self.dfltRole)
            print('\tRule Evaluation:',self.ruleCombAlgo)
            i=0
            while i<len(self.condition):
                print('\t',str(i+1),self.condition[i],'-->',self.result[i])
                i+=1
    
        except Exception as e:
            print('Error Role_Mapping.output: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Role_Mapping.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Role_Mapping.output_pdf',self.name)

        try: 
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Default Role', 0, 0, 'L')
            pdf.cell(0, h, self.dfltRole, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Rule Evaluation', 0, 0, 'L')
            pdf.cell(0, h, self.ruleCombAlgo, 0, 1, 'L')
            i=0
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(175, h, 'Condition', 0, 0, 'L')
            pdf.cell(5, h, '', 0, 0, 'L')
            pdf.cell(100, h, 'Role', 0, 1, 'L')

            while i<len(self.condition):
                pdf.cell(10, h, '', 0, 0, 'L')
#                string=str(i+1)+' '+self.condition[i]+' --> '+self.result[i]
                pdf.cell(10, h, str(i+1), 0, 0, 'L')
                if len(self.condition[i])<80:
                    pdf.cell(165, h, self.condition[i],0,0,'L')
                    pdf.cell(5, h, '', 0, 0, 'L')
                    pdf.cell(100, h, self.result[i],0,1,'L')
                else:
                    pdf.multi_cell(130, h, self.condition[i], 0, 'L')
                    pdf.cell(190, h, '', 0, 0, 'L')
                    pdf.cell(0, h, self.result[i],0,1,'L')
                i+=1
    
        except Exception as e:
            print('Error Role_Mapping.output_pdf: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Role_Mapping.output_pdf',self.name)

            return 1


class Proxy(object):
    """Proxy"""
    total=0

    @staticmethod
    def total():
        print('Total number of Proxy=', Proxy.total)

    def referenced():
        print('Total number of referenced=', Proxy.referenced)

    def used():
        print('Total number of referenced=', Proxy.used)

    def __init__(self, name, description,acctPort,authPort,proxyType,hostname):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=description
        self.acctPort=acctPort
        self.authPort=authPort
        self.proxyType=proxyType
        self.hostname=hostname
#        Proxy.total+=1


    def output(self):
        if DEBUG:
            print('Entering Proxy.output',self.name)

        try: 
            print(self.name,end='')
            print('\tTarget:',self.hostname)
            if self.description:
                print('\tDescription:',self.description)
            print('\tType:',self.proxyType)
            print('\tAuthentication Port:',self.authPort)
            print('\tAccounting Port:',self.acctPort)

        except Exception as e:
            print('Error Proxy.output: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Proxy.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Proxy.output_pdf',self.name)

        try: 
            pdf.cell(0, h, self.name, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Target', 0, 0, 'L')
            pdf.cell(0, h, self.hostname, 0, 1, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Type', 0, 0, 'L')
            pdf.cell(0, h, self.proxyType, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Authentication Port', 0, 0, 'L')
            pdf.cell(0, h, self.authPort, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Accounting Port', 0, 0, 'L')
            pdf.cell(0, h, self.acctPort, 0, 1, 'L')

        except Exception as e:
            print('Error Proxy.output_pdf: ',e)
            return 0
    
        finally:
            pdf.ln(h)
            if DEBUG:
                print('Leaving Proxy.output_pdf',self.name)

            return 1


class Enf_Policy(object):
    """Enforcement Policy"""
    global PROFILES

    total=0

    @staticmethod
    def total():
        print('Total number of Enforcement Policy=', Enf_Policy.total)

    def referenced():
        print('Total number of referenced=', Enf_Policy.referenced)

    def used():
        print('Total number of referenced=', Enf_Policy.used)

    def __init__(self, name):
        self.name=name
        self.referenced=False
        self.ref=[]
        self.used=False
        self.description=''
        self.policyType=''
        self.dfltProfile='[Deny Access Profile]'
        self.ruleCombAlgo=''
        self.condition=[]
        self.result=[]
        self.profiles=[]
#        Enf_Policy.total+=1


    def output(self):
        if DEBUG:
            print('Entering Enf_Policy.output',self.name)

        try: 
            print('Enforcement Policy',self.name)
            if self.description:
                print('\tDescription:',self.description)
            print('\tDefault Profile:',self.dfltProfile)
            print('\tRule Evaluation:',self.ruleCombAlgo)
            i=0
            while i<len(self.condition):
                print('\t',str(i+1),self.condition[i],'-->',self.result[i])
                i+=1
    
        except Exception as e:
            print('Error Enf_Policy.output: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Enf_Policy.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Enf_Policy.output_pdf',self.name)

        try: 
            pdf.ln(h)
            pdf.cell(60, h, 'Enforcement Policy', 0, 0, 'L')
            pdf.cell(0, h, self.name, 0, 1, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Default Profile', 0, 0, 'L')
            pdf.cell(0, h, self.dfltProfile, 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Rule Evaluation', 0, 0, 'L')
            pdf.cell(0, h, self.ruleCombAlgo, 0, 1, 'L')
            i=0
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(160, h, 'Conditions', 0, 0, 'L')
            pdf.cell(140, h, 'Enforement Profiles', 0, 1, 'L')
            while i<len(self.condition):
                pdf.cell(10, h, '', 0, 0, 'L')
#                string=str(i+1)+' '+self.condition[i]+' --> '+self.result[i]
                pdf.cell(10, h, str(i+1), 0, 0, 'L')
                if len(self.condition[i])<80:
                    pdf.cell(150, h, self.condition[i], 0, 0, 'L')
                    if len(self.result[i])<50:
                        pdf.cell(100, h, self.result[i], 0, 1, 'L')
                    else:
                        pdf.multi_cell(100, h, self.result[i], 0, 'L')
                else:
                    pdf.multi_cell(150, h, self.condition[i], 0, 'L')
                    pdf.cell(170, h, '', 0, 0, 'L')
                    if len(self.result[i])<50:
                        pdf.cell(100, h, self.result[i], 0, 1, 'L')
                    else:
                        pdf.multi_cell(100, h, self.result[i], 0, 'L')
#                    pdf.cell(0, h, '', 0, 1, 'L')
                i+=1
    
        except Exception as e:
            print('Error Enf_Policy.output_pdf: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving Enf_Policy.output_pdf',self.name)

            return 1


    def comp_output(self):
        if DEBUG:
            print('Entering Enf_Policy.comp_output',self)

        try: 
            print('Enforcement Policy',self.name)
            if self.description:
                print('\tDescription:',self.description)
            print('\tDefault Profile:',self.dfltProfile)
            print('\tRule Evaluation:',self.ruleCombAlgo)
            i=0
            while i<len(self.condition):
                print('\t',str(i+1),self.condition[i],'-->',self.result[i])
                i+=1
            print('  Referenced Enforcement Profiles (non-default)')
            self.profiles.sort()
            c=0
            for i in self.profiles:
                if i.startswith('[') and i.endswith(']'):
                    continue
                c+=1
                PROFILES[i].output()
            if c==0:
                print('\t***Only Default Profiles***')
    
        except Exception as e:
            print('Error Enf_Policy.comp_output: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Enf_Policy.comp_output',self.name)

            return 1


    def comp_output_pdf(self):
        if DEBUG:
            print('Entering Enf_Policy.comp_output_pdf',self.name)

        try: 
            self.output_pdf()
    
            pdf.ln(h)
            pdf.cell(5, h, '', 0, 0, 'L')
            pdf.cell(0, h, 'Referenced Enforcement Profiles (non-default)', 0, 1, 'L')
            self.profiles.sort()
            c=0
            for i in self.profiles:
                if i.startswith('[') and i.endswith(']'):
                    continue
                c+=1
                PROFILES[i].output()
                PROFILES[i].output_pdf()
            if c==0:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, '***Only Default Profiles***', 0, 1, 'L')
    
        except Exception as e:
            print('Error Enf_Policy.comp_output_pdf: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Enf_Policy.comp_output_pdf',self.name)

            return 1


class Profile(object):
    """Profile"""
    total=0

    @staticmethod
    def total():
        print('Total number of Authentication Sources=', Profile.total)

    def referenced():
        print('Total number of referenced=', Profile.referenced)

    def used():
        print('Total number of referenced=', Profile.used)

    def __init__(self, name):
        self.name=name
        self.used=False
        self.referenced=False
        self.refs=[]
        self.description=''
        self.action=''
        self.type=''
        self.product=''
        self.version=''
        self.template=''
        self.postAuthType=''
        self.autzStatus=''
        self.maxPrivLevel=''
        self.nadGrps=[]
        self.attribList=[]
        self.tacacsNames=[]
        self.tacacsAttrib=[]
        self.tacacsCmd=[]
        self.tacacsArgs=[]
#        Profile.total+=1


    def output(self):

        if DEBUG:
            print('Entering Profile.output',self.name)

        try: 
            print('\t',self.name)
            if self.description:
                print('\t\tDescription:',self.description)
            if self.type:
                print('\t\tType:',self.type)
            if self.action:
                print('\t\tAction:',self.action)
            if self.product:
                print('\t\tProduct:',self.product)
            if self.version:
                print('\t\tVersion:',self.version)
            if self.template:
                print('\t\tTemplate:',self.template)
            if self.postAuthType:
                print('\t\tPost Auth Type:',self.postAuthType)
            if self.maxPrivLevel:
                print('\t\tMax Priv Level:',self.maxPrivLevel)
            if self.nadGrps:
                print("\t\tDevice Group List:")
                c=1
                for i in self.nadGrps:
                    print("\t\t",c,i)
                    c+=1
            if self.tacacsNames:
                print("\t\tSelected Services:")
                c=1
                for i in self.tacacsNames:
                    print("\t\t",c,i)
                    c+=1
            if self.autzStatus:
                if self.autzStatus=='PASS_ADD':
                    print('\t\tAuthorize Attribute Status: ADD')
                else:
                    print('\t\tAuthorize Attribute Status:',self.autzStatus)
            if self.attribList:
                print('\t\tAttributes')
                i=0
                while i<len(self.attribList):
                    if self.type=='Application' or self.type=='Agent' or self.type=='HTTP':
                        print('\t\t',str(i+1),' ',self.attribList[i][1],'=',self.attribList[i][0])
                    else:
                        value=self.attribList[i][1]
                        value=value.replace('|','\n\t\t')
                        if len(value)>=50:   # if long value string on another line
                            value='\n\t\t'+value
                        print('\t\t',str(i+1),' ',self.attribList[i][2],':',self.attribList[i][0],'=',value,sep='')
                    i+=1
            if self.tacacsAttrib:
                print('\t\tAttributes')
                i=0
                while i<len(self.tacacsAttrib):
                    print('\t\t',str(i+1),self.tacacsAttrib[i][3], self.tacacsAttrib[i][0],self.tacacsAttrib[i][2],self.tacacsAttrib[i][1])
                    i+=1
            if self.tacacsCmd:
                print('\t\tTACACS Commands')
                i=0
                while i<len(self.tacacsCmd):
                    print('\t\t\tUnmatched commands')
                    if self.tacacsCmd[i][0]=='false': 
                        print('\t\t\t',str(i+1),self.tacacsCmd[i][1],'Deny')
                    else:
                        print('\t\t\t',str(i+1),self.tacacsCmd[i][1],'Permit')
                    i+=1
            if self.tacacsArgs:
                print('\t\t\tExceptions')
                c=0
                for i in self.tacacsArgs:
                    print('\t\t\t',str(c+1),self.tacacsArgs[c]['cmd'],end='')
                    if self.tacacsArgs[c]['permitUnmatchedArgs']: 
                        print(' and permit unmatched arguments')
                    else:
                        print(' and deny unmatched arguments')
                    for j in i:
                        if j=='permitUnmatchedArgs':
                            continue
                        if j=='cmd':
                            continue
                        print('\t\t\t\t\t',j, end='')
                        if i[j]=='true':
                            print(' permit')
                        else:
                            print(' deny')

                    c+=1
    
        except Exception as e:
            print('Error Profile.output: ',e)
            return 0
    
        finally:
            print()
            if DEBUG:
                print('Leaving Profile.output',self.name)

            return 1


    def output_pdf(self):

        if DEBUG:
            print('Entering Profile.output_pdf',self.name)

        try: 
            pdf.ln(h)
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, self.name, 0, 1, 'L')
            if self.description:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                pdf.cell(0, h, self.description, 0, 1, 'L')
            if self.type:
                pdf.cell(20, h, '', 0, 0, 'L')
                string='Type: '+self.type
                pdf.cell(60, h, 'Type', 0, 0, 'L')
                pdf.cell(0, h, self.type, 0, 1, 'L')
            if self.action:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Action', 0, 0, 'L')
                pdf.cell(0, h, self.action, 0, 1, 'L')
            if self.product:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Product', 0, 0, 'L')
                pdf.cell(0, h, self.product, 0, 1, 'L')
            if self.version:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Version', 0, 0, 'L')
                pdf.cell(0, h, self.version, 0, 1, 'L')
            if self.template:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Template', 0, 0, 'L')
                pdf.cell(0, h, self.template, 0, 1, 'L')
            if self.postAuthType:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Post Auth Type', 0, 0, 'L')
                pdf.cell(0, h, self.postAuthType, 0, 1, 'L')
            if self.maxPrivLevel:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Max Priv Level', 0, 0, 'L')
                pdf.cell(0, h, self.maxPrivLevel, 0, 1, 'L')
            if self.nadGrps:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Device Group List', 0, 0, 'L')
                c=1
                for i in self.nadGrps:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(10, h, str(c), 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
                    c+=1
            if self.tacacsNames:
                pdf.cell(20, h, '', 0, 0, 'L')
                string="Selected Services:"
                pdf.cell(0, h, 'Selected Services', 0, 1, 'L')
                c=1
                for i in self.tacacsNames:
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(10, h, str(c), 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
                    c+=1
            if self.autzStatus:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Authorize Attribute Status', 0, 0, 'L')
                if self.autzStatus=='PASS_ADD':
                    string='ADD'
                else:
                    string=self.autzStatus
                pdf.cell(0, h, string, 0, 1, 'L')
            if self.attribList:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Attributes', 0, 1, 'L')
                i=0
                while i<len(self.attribList):
                    if self.type=='Application' or self.type=='HTTP' or self.type=='Agent':
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(10, h, str(i+1), 0, 0, 'L')
                        pdf.cell(110, h, self.attribList[i][0], 0, 0, 'L')
                        pdf.cell(5, h, '', 0, 0, 'L')
                        if len(self.attribList[i][1])<70:
                            pdf.cell(0, h, self.attribList[i][1], 0, 1, 'L')
                        else:
                            pdf.multi_cell(0,h,string, 'L')
                    else:
                        value=self.attribList[i][1]
#                        value=value.replace('|','\n\t\t')
#                        value=value.replace('|','<NL>')
                        parts=value.split('|')
#                        if len(value)>=50:   # if long value string on another line
#                            value='\n\t\t'+value
                        pdf.cell(20, h, '', 0, 0, 'L')
                        pdf.cell(10, h, str(i+1), 0, 0, 'L')
                        pdf.cell(70, h, self.attribList[i][2], 0, 0, 'L')
                        pdf.cell(5, h, '', 0, 0, 'L')
                        pdf.cell(50, h, self.attribList[i][0], 0, 0, 'L')
                        c=0
                        for j in parts:
                            if c==0:
                                pdf.cell(5, h, '', 0, 0, 'L')
                                c=1
                            else:
                                pdf.cell(160, h, '', 0, 0, 'L')
                            if len(j)<60:
                                pdf.cell(0, h, j, 0, 1, 'L')
                            else:
                                pdf.multi_cell(0,h,j, 'L')
                            
                    i+=1
            if self.tacacsAttrib:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Attributes', 0, 1, 'L')
                i=0
                while i<len(self.tacacsAttrib):
                    pdf.cell(20, h, '', 0, 0, 'L')
                    pdf.cell(10, h, str(i+1), 0, 0, 'L')
                    pdf.cell(40, h, self.tacacsAttrib[i][3], 0, 0, 'L')
                    pdf.cell(40, h, self.tacacsAttrib[i][0], 0, 0, 'L')
                    pdf.cell(40, h, self.tacacsAttrib[i][2], 0, 0, 'L')
                    pdf.cell(40, h, self.tacacsAttrib[i][1], 0, 1, 'L')
                    i+=1
            if self.tacacsCmd:
                pdf.cell(20, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'TACACS Commands', 0, 1, 'L')
                i=0
                while i<len(self.tacacsCmd):
                    pdf.cell(30, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Unmatched commands', 0, 1, 'L')
                    pdf.cell(30, h, '', 0, 0, 'L')
                    if self.tacacsCmd[i][0]=='false': 
                        pdf.cell(10, h, str(i+1), 0, 0, 'L')
                        pdf.cell(40, h, self.tacacsCmd[i][1], 0, 0, 'L')
                        pdf.cell(40, h, 'Deny', 0, 1, 'L')
                    else:
                        pdf.cell(10, h, str(i+1), 0, 0, 'L')
                        pdf.cell(40, h, self.tacacsCmd[i][1], 0, 0, 'L')
                        pdf.cell(40, h, 'Permit', 0, 1, 'L')
                    i+=1
            if self.tacacsArgs:
                pdf.cell(30, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Exceptions', 0, 1, 'L')
                c=0
                for i in self.tacacsArgs:
                    pdf.cell(30, h, '', 0, 0, 'L')
                    pdf.cell(10, h, str(c+1), 0, 0, 'L')
                    pdf.cell(40, h, self.tacacsArgs[c]['cmd'], 0, 0, 'L')
                    if self.tacacsArgs[c]['permitUnmatchedArgs']: 
                        string=' and permit unmatched arguments'
                    else:
                        string=' and deny unmatched arguments'
                    pdf.cell(0, h, string, 0, 1, 'L')
                    for j in i:
                        if j=='permitUnmatchedArgs':
                            continue
                        if j=='cmd':
                            continue
                        pdf.cell(50, h, '', 0, 0, 'L')
                        string=j
                        pdf.cell(0, h, string, 0, 0, 'L')
                        if i[j]=='true':
                            string=' permit'
                        else:
                            string=' deny'
                        pdf.cell(0, h, string, 0, 1, 'L')

                    c+=1
    
        except Exception as e:
            print('Error Profile.output_pdf: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Profile.output_pdf',self.name)

            return 1


class Service(object):
    """Service"""
    global ROLE_MAPPINGS
    global ENF_POLICIES

    total=0

    @staticmethod
    def total():
        print('Total number of Service=', Service.total)

    def __init__(self, name, description,status,protocol):
        self.name=name
        self.used=False
        self.description=description
        self.protocol=protocol
        self.status=status
        self.monitor=False
        self.stripUser=''
        self.acctProxyTargets=False
        self.proxyAccountRequest=False
        self.forwardType=''
        self.useCachedResults=False
        self.postureEnabled=False
        self.remediationUrl=''
        self.remediateEnabled=False
        self.defaultPostureToken='Unknown'
        self.postureActions=[]
        self.audit=False
        self.profiler=False
        self.profMatch=''
        self.profAction=''
        self.authMethods=[]
        self.matchOperator=''
        self.match=[]
        self.template=''
        self.authSrc=[]
        self.autzSrc=[]
        self.roleMapping=''
        self.enfPolicy=''
#        Service.total+=1


    def output_summary(self):

        if DEBUG:
            print('Entering Service.output_summary')

        try: 
                # Skip services that are disabled
            print('\t',self.name,'\t',self.protocol,end='')
            if self.status==False:
                print('\tDisabled')
                return
            else:
                print('\tEnabled')

        except Exception as e:
            print('Error Service.output_summary: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Service.output_summary')

            return 1


    def output_summary_pdf(self):

        if DEBUG:
            print('Entering Service.output_summary_pdf')

        try: 
                # Skip services that are disabled
            pdf.cell(140, h, self.name, 0, 0, 'C')
            pdf.cell(5, h, '', 0, 0, 'L')
            pdf.cell(50, h, self.protocol, 0, 0, 'C')
            pdf.cell(5, h, '', 0, 0, 'L')
            if self.status==False:
#                pdf.set_fill_color(255,0,0)
                pdf.set_text_color(255,0,0)
                string='Disabled'
            else:
#                pdf.set_fill_color(50,205,50)
                pdf.set_text_color(0,255,0)
                string='Enabled'
            pdf.cell(15, h, string, 0, 1, 'C')
#            pdf.set_fill_color(255,255,255)
            pdf.set_text_color(0,0,0)

        except Exception as e:
            print('Error Service.output_summary_pdf: ',e)
            return 0
    
        finally:
            if DEBUG:
                print('Leaving Service.output_summary_pdf')

            return 1


    def output(self):
        if DEBUG:
            print('Entering Service.output',self.name)

        try: 
#            print(self.name)
                # Skip services that are disabled
            if self.status==False:
                print('\tStatus DISABLED!')
                return
            else:
                print('\tStatus Enabled')
            print('\tProtocol',self.protocol)
            if self.description:
                print('\tDescription',self.description)
#            if self.used==False:
#                print('\tService Not used')
#            else:
#                print('\tService Used')
            if self.monitor:
                print('\tMonitor Mode Enabled')
            if self.acctProxyTargets:
                print('\tRADIUS Accounting Proxy Targets')
            if self.proxyAccountRequest:
                print('\tProxy RADIUS Accounting Request')
            if self.forwardType!='':
                print('\tForward Type',self.forwardType)
            if self.useCachedResults:        
                print('\tUse Cached Roles/Postures')
            if self.postureEnabled:        
                print('\tEnforce Posture Compliance')
            if self.audit:        
                print('\tEnforce Audit True')
            if self.profiler:        
                print('\tEnforce Profiler True')
            print('Service Match\t(',self.matchOperator,')',sep='')
            c=0
            for i in self.match:
                c+=1
                print('\t',c, i)
            if len(self.authMethods):
                print('Authentication Methods')
                for i in self.authMethods:
                    print('\t',i)
            if len(self.authSrc):
                print('Authentication Sources')
                for i in self.authSrc:
                    print('\t',i)
            if self.stripUser!='':
                print('\tStrip User ',self.stripUser)
            if len(self.autzSrc):
                print('Further Authorization Sources')
                for i in self.autzSrc:
                    print('\t',i)
            print('Role Mapping: ',end='')
            if self.roleMapping=='':
                print('None')
            else:
                print(self.roleMapping)
                ROLE_MAPPINGS[self.roleMapping].output()
            if self.postureEnabled:
                for i in self.postureActions:
                    print('\t',i)
                print('Posture Compliance')
                print('\tPostureActions')
                c=1
                for i in self.postureActions:
                    print('\t',c,i)
                    c+=1
                print('\tDefault Posture Token',self.defaultPostureToken)
                if self.remediateEnabled:
                    print('\tRemediate End Host',self.remediationUrl)
                if self.remediationUrl!='':
                    print('\tRemediation URL',self.remediationUrl)
            ENF_POLICIES[self.enfPolicy].comp_output()
            if self.profiler==True:
                print('Profiler')
                print('\tMatch',self.profMatch)
                print('\tAction',self.profAction)
            print()
    
        except Exception as e:
            print('Error Service.output: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Service.output',self.name)

            return 1


    def output_pdf(self):
        if DEBUG:
            print('Entering Service.output_pdf',self.name)

        try: 
#            string=self.name
                # Skip services that are disabled
            if self.status==False:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Status', 0, 0, 'L')
                pdf.cell(0, h, 'DISABLED!', 0, 1, 'L')
                return
            else:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Status', 0, 0, 'L')
                pdf.cell(0, h, 'Enabled', 0, 1, 'L')
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(60, h, 'Protocol', 0, 0, 'L')
            pdf.cell(0, h, self.protocol, 0, 1, 'L')
            if self.description:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Description', 0, 0, 'L')
                if len(self.description)<110:
                    pdf.cell(0, h, self.description, 0, 1, 'L')
                else:
                    pdf.multi_cell(110,h,string, 'L')
#            if self.used==False:
#                string='\tService Not used'
#            else:
#                string='\tService Used'
            if self.monitor:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Monitor Mode', 0, 0, 'L')
                pdf.cell(0, h, 'Enabled', 0, 1, 'L')
            if self.acctProxyTargets:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'RADIUS Accounting Proxy Targets', 0, 1, 'L')
            if self.proxyAccountRequest:
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Proxy RADIUS Accounting Request', 0, 1, 'L')
            if self.forwardType!='':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Forward Type', 0, 0, 'L')
                pdf.cell(0, h, self.forwardType, 0, 1, 'L')
            if self.useCachedResults:        
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Use Cached Roles/Postures', 0, 1, 'L')
            if self.postureEnabled:        
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Enforce Posture Compliance', 0, 1, 'L')
            if self.audit:        
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Enforce Audit True', 0, 1, 'L')
            if self.profiler:        
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Enforce Profiler True', 0, 1, 'L')
            string='Service Match ('+self.matchOperator+')'
            pdf.cell(0, h, string, 0, 1, 'L')
            c=0
            for i in self.match:
                c+=1
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(10, h, str(c), 0, 0, 'L')
                pdf.cell(0, h, i, 0, 1, 'L')
            if len(self.authMethods):
                pdf.cell(0, h, 'Authentication Methods', 0, 1, 'L')
                for i in self.authMethods:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
            if len(self.authSrc):
                pdf.cell(0, h, 'Authentication Sources', 0, 1, 'L')
                for i in self.authSrc:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
            if self.stripUser!='':
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Strip User', 0, 0, 'L')
                pdf.cell(0, h, self.stripUser, 0, 1, 'L')
            if len(self.autzSrc):
                pdf.cell(0, h, 'Further Authorization Sources', 0, 1, 'L')
                for i in self.autzSrc:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
            pdf.cell(35, h, 'Role Mapping', 0, 0, 'L')
            if self.roleMapping=='':
                pdf.cell(0, h, 'None', 0, 1, 'L')
            else:
                pdf.cell(0, h, self.roleMapping, 0, 1, 'L')
                ROLE_MAPPINGS[self.roleMapping].output_pdf()
            if self.postureEnabled:
                for i in self.postureActions:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
                pdf.cell(0, h, 'Posture Compliance', 0, 1, 'L')
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(0, h, 'Posture Actions', 0, 1, 'L')
                c=1
                for i in self.postureActions:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(10, h, str(c), 0, 0, 'L')
                    pdf.cell(0, h, i, 0, 1, 'L')
                    c+=1
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Default Posture Token', 0, 0, 'L')
                pdf.cell(0, h, self.defaultPostureToken, 0, 1, 'L')
                if self.remediateEnabled:
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Remediate End Host', 0, 0, 'L')
                    pdf.cell(0, h, self.remediationUrl, 0, 1, 'L')
                if self.remediationUrl!='':
                    pdf.cell(10, h, '', 0, 0, 'L')
                    pdf.cell(60, h, 'Remediation URL', 0, 0, 'L')
                    pdf.cell(0, h, self.remediationUrl, 0, 1, 'L')
            ENF_POLICIES[self.enfPolicy].comp_output_pdf()
            if self.profiler==True:
                pdf.cell(0, h, 'Profiler', 0, 1, 'L')
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Match', 0, 0, 'L')
                pdf.cell(0, h, self.profMatch, 0, 1, 'L')
                pdf.cell(10, h, '', 0, 0, 'L')
                pdf.cell(60, h, 'Action', 0, 0, 'L')
                pdf.cell(0, h, self.profAction, 0, 1, 'L')
    
        except Exception as e:
            print('Error Service.output_pdf: ',e)
            return 0
    
        finally:
#            print()
            if DEBUG:
                print('Leaving Service.output_pdf',self.name)

            return 1


def output_summary_html():
    global SERVICES

    if DEBUG:
        print('Entering Service output_summary_html')

    try: 
        f=open('Services.html','w')
            # Skip services that are disabled
        f.write('<!DOCTYPE html><html><style>')
        f.write('h1 {font-family:arial,verdana,helvetica;}')
        f.write('table {border:3px solid black;border-spacing:0px 0px;border-colapse:border-colapse;max-width:2400px;text-align:center;margin:10px;font-family:arial,verdana,helvetica;}')
        f.write('th {border:1px solid black;height:50px;color:white;background-color:blue;}')
        f.write('td {border:1px solid black;height:30px;color:black;background-color:white;}')
        f.write('</style></head>')
        f.write('<body><h1>ClearPass Service Summary</h1>')
        f.write('<table><col style="width:%5;"><col style="width:%50;"><col style="width:%30;"><col style="width:%15;">')
        f.write('<thead><tr><th>Order</th><th>Service Name</th><th>Type</th><th>Status</th></tr></thead>')

        c=0
        for i in SERVICES:
            c+=1
#            print('SERVICE #',c,i)
            protocol=SERVICES[i].protocol
            status=''
            if protocol=='':
                protocol='<p style="background-color:red;color:white">!!!Could not extract service!!!</p>'
                status='<td style="background-color:red;color:white">Unknown</td></tr>'
            string='<tr><td>'+str(c)+'</td><td>'+i+'</td><td>'+protocol+'</td>'
            f.write(string)
            if status=='':
                if SERVICES[i].status==False:
                    status='<td style="color:red">Disabled</td></tr>'
                else:
                    status='<td style="color:green">Enabled</td></tr>'
            f.write(status)
        f.write('</table></body></html>')
        f.close()

    except Exception as e:
        print('Error Service output_summary_html: ',e)
        return 0

    finally:
        if DEBUG:
            print('Leaving Service output_summary_html.output')

        return 1


def curl_debug(debug_type, debug_msg):
    print("debug(%d): %s" % (debug_type, debug_msg))


def get_operator(value):

    if value=='EQUALS':
        return ' = '
    elif value=='NOT_EQUALS':
        return ' != '
    elif value=='GREATER_THAN':
        return ' > '
    elif value=='GREATER_THAN_OR_EQUALS':
        return ' >= '
    elif value=='LESS_THAN':
        return ' > '
    elif value=='LESS_THAN_OR_EQUALS':
        return ' >= '
#    elif value=='BELONGS_TO':
#        return 'IN'
#    elif value=='NOT_BELONGS_TO':
#        return 'NOT_IN'
    else: 
        return ' '+value+' '


def get_settings(root, namespace, protocol):

    global AUTH_METHODS
    global AUTH_SOURCES
    global ROLE_MAPPINGS
    global ENF_POLICIES

    if DEBUG:
        print('Entering get_settings')

    #pdf.set_font("Arial", 'B', size = 12)
    stripUser=''
    description=''
    for a in root.findall(namespace):
        matched=True
#        print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
        for b in a:
#            print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
            name=b.attrib['name']
            if 'description' in b.attrib:
                description=b.attrib['description']
            if b.attrib['enabled']=='true':
                status=True
            else: 
                status=False
            service=Service(name,description,status,protocol)
            if 'monitor' in b.attrib:
                if b.attrib['monitor']=='true':
                    service.monitor=True
            if 'stripUsername' in b.attrib:
                if b.attrib['stripUsername']=='true':
                    service.stripUsername=True
                    service.stripUser=b.attrib['stripRulesCsv']
            if 'acctProxyTargets' in b.attrib:
                if b.attrib['acctProxyTargets']=='true':
                    service.proxyTargets=True
            if 'proxyAccountRequest' in b.attrib:
                if b.attrib['proxyAccountRequest']=='true':
                    service.proxyAccountRequest=True
            if 'forwardType' in b.attrib:
                if b.attrib['forwardType']:
                    service.forwardType=b.attrib['forwardType']
            if 'useCachedResults' in b.attrib:
                if b.attrib['useCachedResults']:
                    service.useCachedResults=b.attrib['useCachedResults']
            if 'postureEnabled' in b.attrib:
                if b.attrib['postureEnabled']=='true':
                    service.postureEnabled=True
#                    print('postureEnabled b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                    if 'remediationEnabled' in b.attrib:
                        if b.attrib['remediationEnabled']=='true':
                            service.remediateEnabled=True
                            service.remediatationUrl=b.attrib['remediationUrl']
                    service.defaultPostureToken=b.attrib['defaultPostureToken']
            if 'auditEnabled' in b.attrib:
                if b.attrib['auditEnabled']=='true':
                    service.auditEnabled=True
            if 'profilerEnabled' in b.attrib:
                if b.attrib['profilerEnabled']=='true':
                    service.profilerEnabled=True
            for c in b:
                index=0
#                print('c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                if c.tag.endswith('RuleExpression'):
                    service.matchOperator=c.attrib['displayOperator']
                    
                    for d in c:
#                        print('d.tag=',d.tag,', text=',d.text,', attrib=',d.attrib)
                        for e in d:
                            index+=1
#                            print('e.tag=',e.tag,', text=',e.text,', attrib=',e.attrib)
                            if e.tag.endswith('RuleAttribute'):
                                operator=get_operator(e.attrib['operator'])
#                                if e.attrib['operator']=='BELONGS_TO' or e.attrib['operator']=='NOT_BELONGS_TO':
#                                    displayValue='{'+e.attrib['displayValue']+'}'
#                                else:
#                                    displayValue=e.attrib['displayValue']
                                if 'MATCHES' in operator:
                                    displayValue='{'+e.attrib['displayValue']+'}'
                                elif operator==' BELONGS_TO ' or operator==' NOT_BELONGS_TO ':
                                    displayValue='{'+e.attrib['displayValue']+'}'
                                else:
                                    displayValue=e.attrib['displayValue']
                                displayValue=displayValue.replace('&nbsp;','')
#                                print('\t',str(index),' ',e.attrib['type'],':',e.attrib['name'],operator,displayValue,sep='')
                                string=e.attrib['type']+':'+e.attrib['name']+operator+displayValue
                                service.match.append(string)

                elif c.tag.endswith('AuthMethodNameList'):
                    for d in c:
                        if d.tag.endswith('string'):
                            service.authMethods.append(d.text)
                            AUTH_METHODS[d.text].referenced=True
                elif c.tag.endswith('AuthSourceNameList'):
                    for d in c:
                        if d.tag.endswith('string'):
                            service.authSrc.append(d.text)
                            AUTH_SOURCES[d.text].referenced=True
                elif c.tag.endswith('AutzSourceNameList'):
                    for d in c:
                        if d.tag.endswith('string'):
                            service.autzSrc.append(d.text)
                            AUTH_SOURCES[d.text].referenced=True
                elif c.tag.endswith('RoleMappingNameList'):
                    for d in c:
                        if d.tag.endswith('RoleMappingNameList'):
                            continue
                        elif d.tag.endswith('string'):
                            service.roleMapping=d.text
                            ROLE_MAPPINGS[d.text].referenced=True
                elif c.tag.endswith('EnfPolicyNameList'):
                    for d in c.iter():
                        if d.tag.endswith('EnfPolicyNameList'):
                            continue
                        elif d.tag.endswith('string'):
                            service.enfPolicy=d.text
                            ENF_POLICIES[d.text].referenced=True
                elif c.tag.endswith('IpvPostureNameList'):
                    for d in c:
                        if d.tag.endswith('string'):
#                            print('Posture')
                            service.postureActions.append(d.text)

            if 'profilerEnabled' in b.attrib:
                if b.attrib['profilerEnabled']=='true':
                    service.profMatch=b.attrib['categoryCsv']
                    service.profAction=b.attrib['actionProfileName']
    return service


def get_service(service):

    if DEBUG:
        print('Entering get_service: ',service)

#    print('Process',label)       

    try:
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="Service"><Criteria fieldName="name" filterString="'+service+'" match="equals"/></Filter></TipsApiRequest>'

#        curl=pycurl.Curl()

        url='https://'+HOSTNAME+'/tipsapi/config/read/Service'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
#        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print(service,' Output GET request:\n%s' % rsp.text)
    

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        root=ET.fromstring(rsp.text)

        if root[1].text!='Success':
            print('Failed to get Service', service, '!!!')
            print('Check that you can manually export this service')
#            print(service,' Output GET request:\n%s' % rsp.text)
            service=Service('','Failed to receive service!',False,'')
            return service

        if root.find('{http://www.avendasys.com/tipsapiDefs/1.0}TacacsEnforcementServices'):
            service=get_settings(root,'{http://www.avendasys.com/tipsapiDefs/1.0}TacacsEnforcementServices','TACACS')
        elif root.find('{http://www.avendasys.com/tipsapiDefs/1.0}RadiusEnforcementServices'):
            service=get_settings(root,'{http://www.avendasys.com/tipsapiDefs/1.0}RadiusEnforcementServices','RADIUS')
        elif root.find('{http://www.avendasys.com/tipsapiDefs/1.0}AvendaAppAuthServices'):
            service=get_settings(root,'{http://www.avendasys.com/tipsapiDefs/1.0}AvendaAppAuthServices','Application Authentication')
        elif root.find('{http://www.avendasys.com/tipsapiDefs/1.0}AvendaWebAuthServices'):
            service=get_settings(root,'{http://www.avendasys.com/tipsapiDefs/1.0}AvendaWebAuthServices','Web Authentication')
        elif root.find('{http://www.avendasys.com/tipsapiDefs/1.0}RadiusProxyServices'):
            service=get_settings(root,'{http://www.avendasys.com/tipsapiDefs/1.0}RadiusProxyServices','RADIUS Proxy')
        else:
            print('Get_Service: What is this?!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print('Root[0][0].tag=',root[0][0].tag,', attrib=',root[0][0].attrib,', text=',root[0][0].text)
            print(service,' Output GET request:\n%s' % rsp.text)

        return service

    except Exception as e:
        print('Error get_service: ',e)
        print(service,' Output GET request:\n%s' % rsp.text)
        return 0


def get_nadclient(label):

    if DEBUG:
        print('Entering get_nadclient, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="NadClient"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/NadClient'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('NadClient Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        description=''
        if tree[1].text!='Success':
            print('Failed to get NAD Client',label,'!!!')
            return 0

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}NadClient'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            coaPort=a.attrib['coaPort']
#            coaCapable=a.attrib['coaCapable']
            if a.attrib['coaCapable']=='true':
                coaCapable='True'
            else:
                coaCapable='False'
            vendor=a.attrib['vendorName']
            tacacsSecret=a.attrib['tacacsSecret']
            radiusSecret=a.attrib['radiusSecret']
            ip=a.attrib['ipAddress']
            nas=Nad(name,description,coaPort,coaCapable,vendor,tacacsSecret,radiusSecret,ip)
            if 'radsecEnabled' in a.attrib:
                if a.attrib['radsecEnabled']=='true':
                    nas.radEnabled=True
            for b in a.iter():
#                print('b tag=',b.tag,', attrib=',b.attrib)
                if b.tag.endswith('NadClient'):
                    continue
                elif b.tag.endswith('NadClientTags'):
                    name=b.attrib['tagName']
                    value=b.attrib['tagValue']
                    nas.attribDict[name]=value
                elif b.tag.endswith('SnmpRead'):
                    if 'communityString' in b.attrib:
                        nas.snmpReadCommunityString=b.attrib['communityString']
                    if 'snmpVersion' in b.attrib:
                        nas.snmpReadVersion=b.attrib['snmpVersion']
                    if 'user' in b.attrib:
                        nas.snmpReadUser=b.attrib['user']
                    if 'securitylevel' in b.attrib:
                        nas.snmpReadSecurityLevel=b.attrib['securitylevel']
                    if 'authProtocol' in b.attrib:
                        nas.snmpReadAuthProtocol=b.attrib['authProtocol']
                    if 'authKey' in b.attrib:
                        nas.snmpReadAuthKey=b.attrib['authKey']
                    if 'privProtocol' in b.attrib:
                        nas.snmpReadPrivProtocol=b.attrib['privProtocol']
                    if 'privKey' in b.attrib:
                        nas.snmpReadPrivKey=b.attrib['privKey']
                elif b.tag.endswith('SnmpWrite'):
                    if 'communityString' in b.attrib:
                        nas.snmpWriteCommunityString=b.attrib['communityString']
                    if 'snmpVersion' in b.attrib:
                        nas.snmpWriteVersion=b.attrib['snmpVersion']
                    if 'user' in b.attrib:
                        nas.snmpWriteUser=b.attrib['user']
                    if 'securitylevel' in b.attrib:
                        nas.snmpWriteSnmpSecuityLevel=b.attrib['securitylevel']
                    if 'authProtocol' in b.attrib:
                        nas.snmpWriteSnmpAuthProtocol=b.attrib['authProtocol']
                    if 'authKey' in b.attrib:
                        nas.snmpWriteSnmpAuthKey=b.attrib['authKey']
                    if 'privProtocol' in b.attrib:
                        nas.snmpWriteSnmpPrivProtocol=b.attrib['privProtocol']
                    if 'privKey' in b.attrib:
                        nas.snmpWriteSnmpPrivKey=b.attrib['privKey']
                elif b.tag.endswith('SnmpConfig'):
                    if 'readArpInfo' in b.attrib:
                        if b.attrib['readArpInfo']=='true':
                            nas.snmpReadArpInfo=True
                    if 'onConnectEnforcement' in b.attrib:
                        if b.attrib['onConnectEnforcement']=='true':
                            nas.onConnectEnforcement=True
                    if 'onConnectPorts' in b.attrib:
                        nas.onConnectPorts=b.attrib['onConnectPorts']
                    if 'zone' in b.attrib:
                        nas.zone=b.attrib['zone']
                    if 'defaultVlan' in b.attrib:
                        nas.defaultVlan=b.attrib['defaultVlan']
                elif b.tag.endswith('RadSecConfig'):
                    nas.radSrcOverrideIP=b.attrib['sourceOverrideIP']
                    nas.radSANregex=b.attrib['sanRegex']
                    nas.radCNregex=b.attrib['cnRegex']
                    nas.radValCert=b.attrib['validateCert']
                    nas.radIssuer=b.attrib['issuer']
                    nas.radSerialNo=b.attrib['serialNumber']
                else:
                    print('Get_NadClient: What is this? b tag=',b.tag,', attrib=',b.attrib)
                    print('NadClient Output GET request:\n%s' % rsp.text)

    except Exception as e:
        print('Error get_nadclient',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return nas


def get_nadgroup(label):

    if DEBUG:
        print('Entering get_nadgroup, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="NadGroup"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/NadGroup'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('NadClient Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        description=''
        if tree[1].text!='Success':
            print('Failed to get NAD Group',label,'!!!')
            return 0

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}NadGroup'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            members=a.attrib['members']
            membersFormat=a.attrib['membersFormat']
            nadgrp=NadGroup(name,description,members,membersFormat)

    except Exception as e:
        print('Error get_nadgroup',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return nadgrp


def get_authmethod(label):

    if DEBUG:
        print('Entering get_authmethod, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="AuthMethod"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'

        if DEBUG:
            print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/AuthMethod'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthMethod Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get authMethod',label,'!!!')
            return 0

        description=''
        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}AuthMethod'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            method=a.attrib['methodType']
            auth_method=Auth_Method(name, description, method)
            for b in a.iter():
#                print('b tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('NVPair'):
                    i=b.attrib['name']
                    j=b.attrib['value']
                    auth_method.outer[i]=j
                elif b.tag.endswith('InnerMethodNames'):
                    for c in b:
#                        print('c tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                        if c.tag.endswith('string'):
                            if name not in auth_method.inner:
                                auth_method.inner[name]=[]
                            auth_method.inner[name].append(c.text)

    except Exception as e:
        print('Error get_authmethod',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return auth_method


def get_authsource(label):

    attributes=[]

    if DEBUG:
        print('Entering get_authsource, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="AuthSource"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'

        if DEBUG:
            print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/AuthSource'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthSource Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get authSource',label,'!!!')
            return 0

        description=''
        filterName=0
        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}AuthSource'):
            if DEBUG:
                print('AuthSource: a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            if 'isAuthorizationSource' in a.attrib:
                isAuthzSrc=a.attrib['isAuthorizationSource']
            else: 
                isAuthzSrc=''
            authType=a.attrib['type']
            authsrc=Auth_Src(name, description, isAuthzSrc, authType)
            for b in a.iter():
                if DEBUG:
                    print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('AuthSource'):
                    continue
                if b.tag.endswith('NVPair'):
                    name=b.attrib['name']
                    value=b.attrib['value']
                    authsrc.nvPairDict[name]=value
                elif b.tag.endswith('Filters'):
                    continue
                elif b.tag.endswith('Filter'):
#                    paramValue=b.attrib['paramValues']
                    filterQuery=b.attrib['filterQuery']
                    filterName=b.attrib['filterName']
                    authsrc.filterQueryDict[filterName]=filterQuery
                elif b.tag.endswith('Attributes'):
                    continue
                elif b.tag.endswith('Attribute'):
                    attributes=[]
                    attrName=b.attrib['attrName']
                    if 'aliasName' in b.attrib:
                        attributes.append(b.attrib['aliasName'])
                    if 'attrDataType' in b.attrib:
                        attributes.append(b.attrib['attrDataType'])
                    if 'isRole' in b.attrib:
                        isRole=b.attrib['isRole']
                    if 'isUserAttr' in b.attrib:
                        isUserAttr=b.attrib['isUserAttr']
                        if isRole=='true' and isUserAttr=='true':
                            attributes.append('Both')
                        elif isRole=='true':
                            attributes.append('Role')
                        elif isUserAttr=='true':
                            attributes.append('Attribute')
                        else:
                            attributes.append('Attribute')

                    if filterName not in authsrc.filterAttribDict:
                        authsrc.filterAttribDict[filterName]={}
                    if filterName:
                        authsrc.filterAttribDict[filterName][attrName]=attributes
        if DEBUG:
            print('NVPairs',authsrc.nvPairDict)
            print('FilterQuery',authsrc.filterQueryDict)
            print('FilterAttribDict',authsrc.filterAttribDict)

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Backups'):
            if DEBUG:
                print('Backups: a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            nvPairDicts={}
            for b in a.iter():
                if DEBUG:
                    print('\tb.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('list'):
                    if nvPairDicts:
                        authsrc.backup.append(nvPairDicts)
                        nvPairDicts={}
                elif b.tag.endswith('NVPair'):
                    name=b.attrib['name']
                    value=b.attrib['value']
                    nvPairDicts[name]=value
            authsrc.backup.append(nvPairDicts)

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Radius-Pre-Proxy-Attributes'):
            if DEBUG:
                print('Radius-Pre-Proxy-Attributes: a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            for b in a.iter():
                if DEBUG:
                    print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('Attribute'):
                    attrib={}
                    attrib['operator']=b.attrib['oper']
                    attrib['vendor']=b.attrib['vendor']
                    attrib['attrName']=b.attrib['attrName']
                    if 'attrValue' in b.attrib:
                        attrib['attrValue']=b.attrib['attrValue']
                    authsrc.preProxy.append(attrib)

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Radius-Post-Proxy-Attributes'):
            if DEBUG:
                print('Radius-Pre-Proxy-Attributes: a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            for b in a.iter():
                if DEBUG:
                    print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('Attribute'):
                    attrib={}
                    attrib['vendor']=b.attrib['vendor']
                    attrib['attrName']=b.attrib['attrName']
                    if 'attrValue' in b.attrib:
                        attrib['attrValue']=b.attrib['attrValue']
                    authsrc.postProxy.append(attrib)

        # Am I missing other sections???

    except Exception as e:
        print('Error get_authsource',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return authsrc


def get_localuser(label):

    if DEBUG:
        print('Entering get_localuser, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="LocalUser"><Criteria fieldName="userId" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/LocalUser'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthMethod Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get LocalUser',label,'!!!')
            return 0

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}LocalUser'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            userId=a.attrib['userId']
            username=a.attrib['userName']
            password=a.attrib['password']
            passhash=a.attrib['passwordHash']
            passNTLMhash=a.attrib['passwordNtlmHash']
            roleName=a.attrib['roleName']
            enabled=a.attrib['enabled']
            changePwdNextLogin=a.attrib['changePwdNextLogin']
            print('\nLocal UserId: ',userId)
            print('\tEnabled: ',enabled)
            print('\tUsername: ',username)
#            print('\tPassword: ',password)
            print('\tPassword: xxxxxx')
            print('\tPassword Hash: ',passhash)
            print('\tNTLM Password Hash: ',passNTLMhash)
            print('\tRole: ',roleName)
            print('\tChange password at next login: ',changePwdNextLogin)
    except Exception as e:
        print('Error get_localuser',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return 1


def get_role(label):

    if DEBUG:
        print('Entering get_role, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="Role"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/Role'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthMethod Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get Role',label,'!!!')
            return 0

        description=''
        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Role'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            role=Role(name, description)
            if name=='[Machine Authenticated]' or name=='[User Authenticated]':
                role.referenced=True

    except Exception as e:
        print('Error get_role',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return role


def get_rolemapping(label):

    global ROLES
    rolemap=''

    if DEBUG:
        print('Entering get_rolemapping, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="RoleMapping"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/RoleMapping'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthMethod Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        root=ET.fromstring(rsp.text)

        roleMap=0
        if root[1].text!='Success':
            print('Failed to get RoleMapping',label,'!!!')
            return 0

        roleMap=Role_Mapping(label)

        description=''
        index=0
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}RoleMappings'):
            for b in a.iter():
                if b.tag.endswith('RoleMapping'):
                    if b.attrib['name']==label:
                        if 'description' in b.attrib:
                            roleMap.description=b.attrib['description']
                        roleMap.dfltRole=b.attrib['dftRoleName']
                        if b.attrib['dftRoleName'] not in ROLES:
                            print('Error - RoleMapping: Cannot find role',b.attrib['dftRoleName'])
                        else:
#                            print('Role=',d.attrib['displayValue'])
                            ROLES[b.attrib['dftRoleName']].referenced=True
                        for c in b.iter():
                            if c.tag.endswith('Policy'): 
                                roleMap.ruleCombAlgo=c.attrib['ruleCombiningAlgorithm']
                            if c.tag.endswith('Rule'):
                                index+=1
                                count=0
                                result=''
                                for d in c.iter():
                                    if d.tag.endswith('Expression'):
                                        logic=d.attrib['operator']
    
                                    if d.tag.endswith('RuleAttribute'):
                                        displayValue=d.attrib['displayValue'].replace('<br>',',')
                                        displayValue=displayValue.replace('&nbsp;','')
                                        operator=get_operator(d.attrib['operator'])
                                        if operator=='IN' or operator=='NOT_IN':
                                            displayValue='{'+displayValue+'}'
                                        count+=1
                                        if count>1:     # multiple rules in the condition
                                            if logic=='and':
#                                                rolemap+=' AND\n\t\t'+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                                rolemap+=' AND '+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                            if logic=='or':
#                                                rolemap+=' OR\n\t\t'+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                                rolemap+=' OR '+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                        else:
                                            rolemap=d.attrib['type']+':'+d.attrib['name']+operator+displayValue
    
                                    if d.tag.endswith('RuleResult'):
                                        result+=d.attrib['displayValue']
                                        roleMap.result.append(d.attrib['displayValue'])
                                        if d.attrib['displayValue'] not in ROLES:
                                            print('Error - RoleMapping: Cannot find role',d.attrib['displayValue'])
                                        else:
                                            ROLES[d.attrib['displayValue']].referenced=True

                                roleMap.condition.append(rolemap)

    
    except Exception as e:
        print('Error get_rolemapping',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return roleMap


def get_enforcementpolicy(label):

    global PROFILES

    rolemap=''

    if DEBUG:
        print('Entering get_enforcementpolicy, label',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="EnforcementPolicy"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/EnforcementPolicy'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
##        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('EnforcementPolicy Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        root=ET.fromstring(rsp.text)

        enfPolicy=0
        if root[1].text!='Success':
            print('Failed to get Enforcement Policy',label,'!!!')
            return 0

        enfPolicy=Enf_Policy(label)

        description=''
        index=0
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}EnforcementPolicies'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            for b in a.iter():
#                print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnforcementPolicy'):
                    if b.attrib['name']==label:
                        if 'description' in b.attrib:
                            enfPolicy.description=b.attrib['description']
                        enfPolicy.policyType=b.attrib['policyType']
                        enfPolicy.dfltProfile=b.attrib['defaultProfileName']
                        for c in b.iter():
#                            print('c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                            if c.tag.endswith('}Policy'): 
                                enfPolicy.ruleCombAlgo=c.attrib['ruleCombiningAlgorithm']
                            if c.tag.endswith('Rule'):
                                index+=1
                                count=0
                                result=''
                                for d in c.iter():
                                    if d.tag.endswith('Expression'):
                                        logic=d.attrib['operator']
    
                                    if d.tag.endswith('RuleAttribute'):
                                        displayValue=d.attrib['displayValue'].replace('<br>',',')
                                        displayValue=displayValue.replace('&nbsp;','')
                                        operator=get_operator(d.attrib['operator'])
                                        if operator=='IN' or operator=='NOT_IN':
                                            displayValue='{'+displayValue+'}'
                                        count+=1
                                        if count>1:     # multiple rules in the condition
                                            if logic=='and':
#                                                rolemap+=' AND\n\t\t'+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                                rolemap+=' AND '+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                            if logic=='or':
#                                                rolemap+=' OR\n\t\t'+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                                rolemap+=' OR '+d.attrib['type']+':'+d.attrib['name']+operator+displayValue
                                        else:
                                            rolemap=d.attrib['type']+':'+d.attrib['name']+operator+displayValue
    
                                    if d.tag.endswith('RuleResult'):
                                        result+=d.attrib['displayValue']
                                        for i in d.attrib['displayValue'].split(', '):
                                            if i not in enfPolicy.profiles:
                                                enfPolicy.profiles.append(i)

                                enfPolicy.condition.append(rolemap)
                                enfPolicy.result.append(result)

        profile=0
        description=''
        # Extract the Profiles from the EnforcementPolicies
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}RadiusEnfProfiles'):
#            print('\nRADIUS Profiles')
    #        print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
    #            print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnfProfiles'):
                    continue
                if b.tag.endswith('EnfProfile'):
                    name=b.attrib['name']
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
                    profile.type='RADIUS'
    #                print('In here: b.tag=',b.tag,', attrib=',b.attrib)
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    if 'productVersion' in b.attrib:
                        profile.version=b.attrib['productVersion']
                    if 'product' in b.attrib:
                        profile.product=b.attrib['product']
                    profile.action=b.attrib['action']
                    for c in b:
                        if c.tag.endswith('AttributeList'):
                            for d in c:
                                attributes=[]
                                attributes.append(d.attrib['name'])
                                attributes.append(d.attrib['displayValue'])
                                attributes.append(d.attrib['type'])
#                                value=d.attrib['displayValue']
#                                value=value.replace('|','\n\t\t')
                                profile.attribList.append(attributes)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        elif c.tag.endswith('ArubaOSSwitchRoleConfig'):
                            print('\t\tDUR Profile',name,'is not currently supported')
#                            print('Profile',name,'ArubaOSSwitchRoleConfig: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
#                            print('Output GET request:\n%s' % rsp.text)
                            for d in c:
                                if d.tag.endswith('Attribute'):
                                    attributes.append(d.attrib['name'])
                                    attributes.append(d.attrib['value'])
                        elif c.tag.endswith('aosRoleConfig'):
                            print('\t\tDUR Profile',name,'is not currently supported')
#                            print('Profile',name,'aosRoleConfig: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
#                            print('Output GET request:\n%s' % rsp.text)
                            for d in c:
                                if d.tag.endswith('acl'):
                                    attributes.append(d.attrib['name'])
                                    attributes.append(d.attrib['type'])
                        else:
                            print('Get_Profile RADIUS',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
    
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}RadiusCoAEnfProfiles'):
#            print('\nRADIUS CoA Enforcement Profiles')
    #        print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
    #            print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnfProfiles'):
                    continue
                if b.tag.endswith('EnfProfile'):
                    name=b.attrib['name']
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
                    profile.type='RADIUS CoA'
    #                print('In here: b.tag=',b.tag,', attrib=',b.attrib)
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    profile.template=b.attrib['template']
                    profile.action=b.attrib['action']
                    for c in b:
                        if c.tag.endswith('AttributeList'):
                            for d in c:
                                attributes=[]
                                attributes.append(d.attrib['name'])
                                attributes.append(d.attrib['displayValue'])
                                attributes.append(d.attrib['type'])
                                profile.attribList.append(attributes)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        else:
                            print('Get_Profile RADIUS CoA',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}GenericEnfProfiles'):
#            print('\nGeneric Enforcement Profiles')
#            print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
#                print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnfProfiles'):
                    continue
                if b.tag.endswith('EnfProfile'):
                    name=b.attrib['name']
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
#                    print('In here: b.tag=',b.tag,', attrib=',b.attrib)
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    profile.type=b.attrib['type']
                    profile.action=b.attrib['action']
                    for c in b:
#                        print('c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                        if c.tag.endswith('ProfileParams'):
                            attributes=[]
                            attributes.append(c.attrib['name'])
                            attributes.append(c.attrib['displayValue'])
                            profile.attribList.append(attributes)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        else:
                            print('Get_Profile Generic',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
    
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}PostAuthEnfProfiles'):
#            print('\nPost Authentication Enforcement Profiles')
#            print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
#                print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnfProfiles'):
                    continue
                if b.tag.endswith('EnfProfile'):
                    name=b.attrib['name']
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
                    profile.type='Post Auth'
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    profile.postAuthType=b.attrib['postAuthType']

                    for c in b:
                        if c.tag.endswith('AttributeList'):
                            for d in c:
                                attributes=[]
                                attributes.append(d.attrib['name'])
                                attributes.append(d.attrib['displayValue'])
                                attributes.append(d.attrib['type'])
                                profile.attribList.append(attributes)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        else:
                            print('Get_Profile PostAuth',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                
        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}TacacsEnfProfiles'):
#            print('\nTACACS Enforcement Profiles')
#            print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
#                print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('EnfProfiles'):
                    continue
                if b.tag.endswith('EnfProfile'):
                    name=b.attrib['name']
#                    print('Name=',name)
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
                    profile.type='TACACS'
                    profile.action='Accept'
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    profile.autzStatus=b.attrib['autzStatus']
                    profile.maxPrivLevel=b.attrib['maxPrivLevel']
                    for c in b:
#                    for c in b.iter():
#                        print('c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                        if c.tag.endswith('ServiceNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.tacacsNames.append(d.text)
                        elif c.tag.endswith('ServiceAttrList'):
                            for d in c:
#                                print('d.tag=',d.tag,', text=',d.text,', attrib=',d.attrib)
                                if d.tag.endswith('RulesCondition'):
                                    attributes=[]
                                    attributes.append(d.attrib['name'])
                                    attributes.append(d.attrib['valueDispName'])
                                    attributes.append(d.attrib['oper'])
                                    attributes.append(d.attrib['type'])
                                    profile.tacacsAttrib.append(attributes)
                        elif c.tag.endswith('CmdAutzSet'):
#                            print('Profile',name,'CmdAutzSet')
                            commands=[]
                            commands.append(c.attrib['permitUnmatchedCmds'])
                            commands.append(c.attrib['type'])
                            profile.tacacsCmd.append(commands)
                            cmds=[]
                            dic={}
                            for d in c.iter():
#                                print('d.tag=',d.tag,', text=',d.text,', attrib=',d.attrib)
                                if d.tag.endswith('Command'):
                                    if dic:
                                        profile.tacacsArgs.append(dic)
                                    dic={}
                                    dic['permitUnmatchedArgs']=d.attrib['permitUnmatchedArgs']
                                    dic['cmd']=d.attrib['cmd']
                                if d.tag.endswith('Argument'):
                                    dic[d.attrib['cmdArg']]=d.attrib['permit']
                            if dic:
                                profile.tacacsArgs.append(dic)
#                            print('Args=',profile.tacacsArgs)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        else:
                            print('Get_Profile TACACS',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)

        for a in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}AgentEnfProfiles'):
#            print('\nAgent Enforcement Profiles')
#            print('Here a.tag=',a.tag,', attrib=',a.attrib)
            for b in a.iter():
#                print('b.tag=',b.tag,', text=',b.text,', attrib=',b.attrib)
                if b.tag.endswith('AgentEnfProfiles'):
                    continue
                if b.tag.endswith('AgentEnfProfile'):
                    name=b.attrib['name']
                    profile=PROFILES[name]
                    if profile.referenced==True:
                        continue
                    profile.referenced=True
                    if 'description' in b.attrib:
                        profile.description=b.attrib['description']
                    profile.type=b.attrib['agentEnfType']
                    for c in b:
#                        print('c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
                        if c.tag.endswith('ProfileParams'):
                            attributes=[]
                            attributes.append(c.attrib['name'])
                            attributes.append(c.attrib['displayValue'])
                            attributes.append('')
                            profile.attribList.append(attributes)
                        elif c.tag.endswith('NadGroupNameList'):
                            for d in c:
                                if d.tag.endswith('string'):
                                    profile.nadGrps.append(d.text)
                        else:
                            print('Get_Profile Agent',name,': What is this?: c.tag=',c.tag,', text=',c.text,', attrib=',c.attrib)
    
    except Exception as e:
        print('Error get_enforcementpolicy',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return enfPolicy


def get_profile(label):

    if DEBUG:
        print('Entering get_profile, label=',label)

#    print('Process',label)       

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="EnforcementProfile"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/EnforcementProfile'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
##        curl.setopt(curl.POSTFIELDS, xml)
##        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('Profile Output GET request:\n%s' % rsp.text)
        print('Profile Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get Enforcement Profile',label,'!!!')
            return 0

        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Profile'):
            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            print('Role ',name)
            if description:
                print('\tDescription:',description)
    except Exception as e:
        print('Error get_profile',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return 1


def get_proxy(label):

    if DEBUG:
        print('Entering get_proxy, label=',label)

#    print('Process',label)       

    proxy=0

    try: 
#        buff=io.BytesIO()
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"><TipsHeader version="6.0"/><Filter entity="ProxyTarget"><Criteria fieldName="name" filterString="'+label+'" match="equals"/></Filter></TipsApiRequest>'
#        print('xml=',xml)

#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/read/ProxyTarget'
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#            # Ignore the certificate
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ['Content-Type: application/xml'])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print('AuthMethod Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        tree=ET.fromstring(rsp.text)

        if tree[1].text!='Success':
            print('Failed to get Proxy',label,'!!!')
            return 0

        description=''
        for a in tree.findall('.//{http://www.avendasys.com/tipsapiDefs/1.0}Proxy'):
#            print('a.tag=',a.tag,', text=',a.text,', attrib=',a.attrib)
            name=a.attrib['name']
            if 'description' in a.attrib:
                description=a.attrib['description']
            acctPort=a.attrib['acctPort']
            authPort=a.attrib['authPort']
            proxyType=a.attrib['type']
            hostname=a.attrib['hostName']
            proxy=Proxy(label,description,acctPort,authPort,proxyType,hostname)

    except Exception as e:
        print('Error get_proxy',label,':',e)
        print('Data',rsp.text)
        return 0

    finally:
        return proxy


def get_namelist(entity):

    stuff=[]
    try: 
        xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?> <TipsApiRequest xmlns="http://www.avendasys.com/tipsapiDefs/1.0"> <TipsHeader version="6.0"/> <EntityNameList entity="'+entity+'"/></TipsApiRequest>'
#        print('xml=',xml)
#        buff=io.BytesIO()
#        curl=pycurl.Curl()
#
        url='https://'+HOSTNAME+'/tipsapi/config/namelist/'+entity
##        print('URL=',url)
#        curl.setopt(curl.URL, url)
#            # Skips SSL certificate validation!
#            # DEBUG
##        curl.setopt(curl.VERBOSE, 1)
#
#        curl.setopt(curl.SSL_VERIFYPEER, False)
#        curl.setopt(curl.SSL_VERIFYHOST, False)
#        curl.setopt(curl.USERPWD, '%s:%s' %(USERNAME,PASSWORD))
#        curl.setopt(curl.POSTFIELDS, xml)
#        curl.setopt(curl.POSTFIELDSIZE_LARGE, len(xml))
#        curl.setopt(curl.WRITEDATA, buff)
#        curl.setopt(curl.HTTPHEADER, ["Content-Type: application/xml"])
#            #DEBUG
##        curl.setopt(curl.DEBUGFUNCTION, curl_debug)
#
#        curl.perform()
#        curl.close()
#        get_body = buff.getvalue()
#        rsp=get_body.decode('utf8')
        rsp=requests.post(url,data=xml,auth=HTTPBasicAuth(USERNAME,PASSWORD),verify=False)
        if DEBUG:
            print(entity,' Output GET request:\n%s' % rsp.text)

        if rsp.status_code!=200:
            print('Failed get_namelist',rsp)
            return 0
        root=ET.fromstring(rsp.text)

        for child in root:
#            print('Child tag=',child.tag,', attrib=',child.attrib,', text=',child.text)
            if child.tag.endswith('StatusCode'):
                if child.text!='Success':
                    return ''

        for entities in root.findall('{http://www.avendasys.com/tipsapiDefs/1.0}EntityNameList'):
            for j in child:
                stuff.append(j.text)

#        print('stuff=',stuff)

    except Exception as e:
        print('Error get_namelist: ',e)
        print('Data',rsp.text)
        return 0

    finally:
        return stuff


if __name__=='__main__':

#    global SERVICES
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    print('Welcome to ClearPass Services Report')

    now=datetime.today()
    expire=datetime.strptime(EXPIRE, '%Y-%m-%d')
    print('WARNING: This code will expire on ',expire)
    if now>expire: 
        print('The code has expired')
        sys.exit(0)

    index=1
    argc=len(sys.argv)
    if 5<=argc<=8:
        if sys.argv[1]=='-D':
            DEBUG=True
            index=2
        if sys.argv[index]=='-h':
            index+=1
            HOSTNAME=sys.argv[index]
            index+=1
        else:
            print('Usage: python services.py [-D] -h <hostname> -u <username> {-p <password>}, where -D=debug')
            sys.exit()
        if sys.argv[index]=='-u':
            index+=1
            USERNAME=sys.argv[index]
            index+=1
        else:
            print('Usage: python services.py [-D] -h <hostname> -u <username> {-p <password>}, where -D=debug')
            sys.exit()
        if index<argc:
            if sys.argv[index]=='-p':
                index+=1
                PASSWORD=sys.argv[index]
            else:
                print('Usage: python services.py [-D] -h <hostname> -u <username> {-p <password>}, where -D=debug')
                sys.exit()
        if PASSWORD=='':
            PASSWORD=getpass(prompt='Please enter appexternal password: ')
    else:
        print('Usage: python services.py [-D] -h <hostname> -u <username> {-p <password>}, where -D=debug')
        sys.exit()

    print('Processing Authentication Methods')
    authmethods=get_namelist('AuthMethod')
    if authmethods==[]:
        sys.exit(1)
    for i in authmethods:
        print('\t',i)
        auth_method=get_authmethod(i)
        if auth_method==0:
            print('Failed to get_authmethod ',i)
            exit()
        AUTH_METHODS[i]=auth_method
    for i in AUTH_METHODS:
        AUTH_METHODS_SORTED.append(i)
    AUTH_METHODS_SORTED.sort()

    print('Processing Authentication Sources')
    authsources=get_namelist('AuthSource')
    for i in authsources:
        print('\t',i)
        auth_src=get_authsource(i)
        if auth_src==0:
            print('Failed to get_authsource ',i)
            exit()
        AUTH_SOURCES[i]=auth_src
    for i in AUTH_SOURCES:
        AUTH_SOURCES_SORTED.append(i)
    AUTH_SOURCES_SORTED.sort()

#    localusers=get_namelist('LocalUser')
#    print('\nLocal Users')
#    print('===========')
#    for i in localusers:
#        get_localuser(i)
#

    print('Processing Roles')
    roles=get_namelist('Role')
    for i in roles:
        print('\t',i)
        role=get_role(i)
        if roles==0:
            print('Failed to get_role ',i)
            exit()
        ROLES[i]=role
    for i in ROLES:
        ROLES_SORTED.append(i)
    ROLES_SORTED.sort()

    print('Processing Role Mapping')
    role_mappings=get_namelist('RoleMapping')
    for i in role_mappings:
        print('\t',i)
        roleMapping=get_rolemapping(i)
        if roleMapping==0:
            continue
        ROLE_MAPPINGS[i]=roleMapping
    for i in ROLE_MAPPINGS:
        ROLE_MAPPINGS_SORTED.append(i)
    ROLE_MAPPINGS_SORTED.sort()

###!!!! Alas the command to read the Profiles is not working !!!!###
### Because of this I'm pulling the Profile defails out of the EnforcementPolicy request ###
##    print('\nEnforcement Profiles')
##    print('====================')
##    for i in profiles:
##       print(i)
##        get_PROFILES(i)
    print('Processing Enforcement Profiles')
    profiles=get_namelist('EnforcementProfile')
    for i in profiles:
        print('\t',i)
        PROFILES[i]=Profile(i)
    for i in PROFILES:
        PROFILES_SORTED.append(i)
    PROFILES_SORTED.sort()

    print('Processing Enforcement Policies')
    enfpolicies=get_namelist('EnforcementPolicy')
    for i in enfpolicies:
        print('\t',i)
        enfPolicy=get_enforcementpolicy(i)
        if enfPolicy==0:
            continue
        ENF_POLICIES[i]=enfPolicy
    for i in ENF_POLICIES:
        ENF_POLICIES_SORTED.append(i)
    ENF_POLICIES_SORTED.sort()

    print('Processing Services')
    services=get_namelist('Service')
    for i in services:
        print('\t',i)
        SERVICES[i]=get_service(i)
    for i in SERVICES:
        SERVICES_SORTED.append(i)
    SERVICES_SORTED.sort()

    print('Processing Network Access Devices')
    nadclients=get_namelist('NadClient')
    for i in nadclients:
        print('\t',i)
        nads=get_nadclient(i)
        if nads==0:
            print('Failed to get_nadclient ',i)
        NAD_CLIENTS[i]=nads
    for i in NAD_CLIENTS:
        NAD_CLIENTS_SORTED.append(i)
    NAD_CLIENTS_SORTED.sort()

    print('Processing Network Access Devices Groups')
    nadgroup=get_namelist('NadGroup')
    for i in nadgroup:
        print('\t',i)
        nadgrp=get_nadgroup(i)
        if nadgrp==0:
            print('Failed to get_nadgrp ',i)
        NAD_GROUPS[i]=nadgrp
    for i in NAD_GROUPS:
        NAD_GROUPS_SORTED.append(i)
    NAD_GROUPS_SORTED.sort()

    print('Processing Proxy Targets')
    proxies=get_namelist('ProxyTarget')
    for i in proxies:
        print('\t',i)
        proxy=get_proxy(i)
        if proxy==0:
            print('Failed to get_proxy ',i)
        PROXIES[i]=proxy
    for i in PROXIES:
        PROXIES_SORTED.append(i)
    PROXIES_SORTED.sort()


    pdf = FPDF(orientation='L', unit='mm', format='A4')
    pdf.set_title('ClearPass Services')
    pdf.set_author('Derin Mellor')
    pdf.add_page()

    string='Configuration Output'
    print('\n',string,sep='')
    print('====================')
    pdf.set_font("Arial", 'B', size = 18)
    pdf.ln(H)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Services = '+str(len(SERVICES))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", 'B', size = 11)
    c=0
    pdf.set_fill_color(0,0,255)
    pdf.set_text_color(255,255,255)
    pdf.cell(12,h,'Order',0,0,'L', fill=True)
    pdf.cell(5,h,'',0,0,'L',fill=True)
    pdf.cell(140,h,'Service Name',0,0,'C',fill=True)
    pdf.cell(5,h,'',0,0,'L',fill=True)
    pdf.cell(50,h,'Type',0,0,'C',fill=True)
    pdf.cell(5,h,'',0,0,'L',fill=True)
    pdf.cell(15,h,'Status',0,1,'C',fill=True)
    pdf.set_fill_color(255,255,255)
    pdf.set_text_color(0,0,0)
    pdf.set_font("Arial", size = 11)
    for i in SERVICES:
        c+=1
        string=str(c)
        print(string,end='')
        pdf.cell(12, h, string, 0, 0, 'L')
        pdf.cell(5, h, '', 0, 0, 'L')
        if i=='':
            string='FAILED TO EXPORT SERVICE'
            print('\t',string,'\n\n',end='')
            +'\tFAILED TO EXPORT SERVICE!\n\n'
            pdf.cell(10, h, string, 0, 1, 'L')
        else:
            SERVICES[i].output_summary()
            SERVICES[i].output_summary_pdf()
    output_summary_html()

    pdf.set_font("Arial", 'B', size = 18)
    pdf.ln(H)
    pdf.cell(0, h, 'Service Details', 0, 1, 'L')
    c=0
    for i in SERVICES:
        c+=1
#        if SERVICES[i].name=='':
        if i=='':
            pdf.set_font("Arial", 'B', size = 16)
            string='SERVICE #'+str(c)+'\t'+i+'\tFAILED TO EXPORT SERVICE!\n\n'
            print(string)
            pdf.cell(0, h, string, 0, 1, 'L')
            pdf.set_font("Arial", size = 11)
        else:
            pdf.set_font("Arial", 'B', size = 16)
            string='SERVICE #'+str(c)+'\t'+i
            print(string)
            pdf.cell(0, h, string, 0, 1, 'L')
            pdf.set_font("Arial", size = 11)
            SERVICES[i].output()
            SERVICES[i].output_pdf()
        pdf.ln(h)
    print()
#    print('\nUnused Services')
#    c=0
#    for i in SERVICES_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if SERVICES[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')


    string='Authentication Methods'
    print('\n\n',string,sep='')
    print('======================')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Auth Methods = '+str(len(AUTH_METHODS))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Auth Methods'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in AUTH_METHODS_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        c+=1
        AUTH_METHODS[i].output()
        AUTH_METHODS[i].output_pdf()
    if c==0:
        sting='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
    string='Unreferenced Auth Methods'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in AUTH_METHODS_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if AUTH_METHODS[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
            pdf.cell(0, h, string, 0, 1, 'L')
    if c==0:
        sting='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Auth Methods')
#    c=0
#    for i in AUTH_METHODS_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if AUTH_METHODS[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')

    string='Authentication and Authorization Sources'
    print('\n\n',string,sep='')
    print('========================================')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Auth Sources = '+str(len(AUTH_SOURCES))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Auth Sources'
    print('\n',string)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in AUTH_SOURCES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if AUTH_SOURCES[i].referenced:
            c+=1
            AUTH_SOURCES[i].output()
            AUTH_SOURCES[i].output_pdf()
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
    string='Unreferenced Auth Sources'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in AUTH_SOURCES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if AUTH_SOURCES[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
            pdf.cell(0, h, string, 0, 1, 'L')
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Auth Sources')
#    c=0
#    for i in AUTH_SOURCES_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if AUTH_SOURCES[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')

    string='Roles'
    print('\n\n',string,sep='')
    print('============')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Roles = '+str(len(ROLES))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Roles'
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ROLES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ROLES[i].referenced:
            c+=1
            ROLES[i].output()
            ROLES[i].output_pdf()
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
    string='Unreferenced Roles'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ROLES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ROLES[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, string, 0, 1, 'L')
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Role Mapping')
#    c=0
#    for i in ROLES_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if ROLES[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')


    string='Role Mapping'
    print('\n\n',string,sep='')
    print('============')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Role Mappings = '+str(len(ROLE_MAPPINGS))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Role Mapping'
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ROLE_MAPPINGS_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ROLE_MAPPINGS[i].referenced:
            c+=1
            string='\n'+i
            print(string)
            pdf.ln(h)
            pdf.cell(0, h, i, 0, 1, 'L')
            ROLE_MAPPINGS[i].output()
            ROLE_MAPPINGS[i].output_pdf()
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
    string='Unreferenced Role Mapping'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(5, h, '', 0, 0, 'L')
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ROLE_MAPPINGS_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ROLE_MAPPINGS[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, string, 0, 1, 'L')
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Role Mapping')
#    c=0
#    for i in ROLE_MAPPINGS_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if ROLE_MAPPINGS[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')
    string='Special [Guest Roles] Role Mapping'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    if '[Guest Roles]' in ROLE_MAPPINGS:
        ROLE_MAPPINGS['[Guest Roles]'].output()
        ROLE_MAPPINGS['[Guest Roles]'].output_pdf()
    else:
        string='[Guest Roles] could not be retrieved!'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')

    string='Enforcement Policies'
    print('\n\n',string,sep='')
    print('====================')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Enforcement Policies = '+str(len(ENF_POLICIES))
    print(string)
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Enforcement Policies'
    print('\n',string)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ENF_POLICIES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ENF_POLICIES[i].referenced:
            c+=1
            ENF_POLICIES[i].output()
            ENF_POLICIES[i].output_pdf()
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
    string='Unreferenced Enforcement Policies'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in ENF_POLICIES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if ENF_POLICIES[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
    if c==0:
        string='None'
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Enforcement Policies')
#    c=0
#    for i in ENF_POLICIES_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if ENF_POLICIES[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')

    string='Enforcement Profiles'
    print('\n\n',string,sep='')
    print('====================')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Enforcement Profiles = '+str(len(PROFILES))
    print(string)
    pdf.cell(5, h, '', 0, 0, 'L')
    pdf.cell(0, h, string, 0, 1, 'L')
    string='Referenced and non-default Enforcement Profiles'
    print('\n',string)
    pdf.cell(0, h, string, 0, 1, 'L')
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='RADIUS':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='RADIUS CoA':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='TACACS':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='Post Auth':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='Application':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='HTTP':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if PROFILES[i].type=='Agent':
            if i.startswith('[') and i.endswith(']'):
                continue
            if PROFILES[i].referenced:
                PROFILES[i].output()
                PROFILES[i].output_pdf()
    for i in PROFILES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if PROFILES[i].type=='RADIUS':
            continue
        if PROFILES[i].type=='RADIUS CoA':
            continue
        if PROFILES[i].type=='TACACS':
            continue
        if PROFILES[i].type=='Post Auth':
            continue
        if PROFILES[i].type=='Application':
            continue
        if PROFILES[i].type=='HTTP':
            continue
        if PROFILES[i].type=='Agent':
            continue
        if PROFILES[i].type=='':        # Occurs if it is not referenced
            continue
        string=i+' Unknown Profile type: '+PROFILES[i].type
        print(string)
        pdf.cell(0, h, string, 0, 1, 'L')

    string='Unreferenced Enforcement Profiles'
    print('\n',string)
    pdf.ln(h)
    pdf.cell(0, h, string, 0, 1, 'L')
    c=0
    for i in PROFILES_SORTED:
        if i.startswith('[') and i.endswith(']'):
            continue
        if PROFILES[i].referenced==False:
            c+=1
            string='\t'+i
            print(string)
            pdf.cell(10, h, '', 0, 0, 'L')
            pdf.cell(0, h, string, 0, 1, 'L')
    if c==0:
        string='None'
        print(string)
        pdf.cell(10, h, '', 0, 0, 'L')
        pdf.cell(0, h, string, 0, 1, 'L')
#    print('Unused Profiles')
#    c=0
#    for i in PROFILES_SORTED:
#        if i.startswith('[') and i.endswith(']'):
#            continue
#        if PROFILES[i].used==False:
#            c+=1
#            print('\t',i)
#    if c==0:
#        print('None')

    string='NAD Clients'
    print('\n\n',string,sep='')
    print('===========')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of NAD clients = '+str(len(NAD_CLIENTS))
    print(string)
    pdf.cell(5, h, '', 0, 0, 'L')
    pdf.cell(0, h, string, 0, 1, 'L')
    for i in NAD_CLIENTS_SORTED:
        NAD_CLIENTS[i].output()
        NAD_CLIENTS[i].output_pdf()
  
    string='NAD Groups'
    print('\n\n',string,sep='')
    print('==========')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of NAD Group = '+str(len(NAD_GROUPS))
    print(string)
    pdf.cell(5, h, '', 0, 0, 'L')
    pdf.cell(0, h, string, 0, 1, 'L')
    for i in NAD_GROUPS_SORTED:
        NAD_GROUPS[i].output()
        NAD_GROUPS[i].output_pdf()
    
    string='Proxies'
    print('\n\n',string,sep='')
    print('=======')
    pdf.ln(H)
    pdf.set_font("Arial", 'B', size = 16)
    pdf.cell(0, h, string, 0, 1, 'L')
    pdf.set_font("Arial", size = 11)
    string='Number of Proxies = '+str(len(PROXIES))
    print(string)
    pdf.cell(5, h, '', 0, 0, 'L')
    pdf.cell(0, h, string, 0, 1, 'L')
    for i in PROXIES_SORTED:
        PROXIES[i].output()
        PROXIES[i].output_pdf()

    pdf.output('PolicyManagerCnfg.pdf')
