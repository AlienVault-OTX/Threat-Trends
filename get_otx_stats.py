#!/usr/bin/env python
# Gets a dump of report data from OTX for statistics / trends
# Forked from loki by Florian Roth

from OTXv2 import OTXv2
import re
import os
import sys
import traceback
import argparse
import tldextract

OTX_KEY = ''


HASH_WHITELIST = ['e617348b8947f28e2a280dd93c75a6ad','125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
                  '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20']
DOMAIN_WHITELIST = ['proofpoint.com']

class WhiteListedIOC(Exception): pass

class OTXReceiver():

    def __init__(self):
        self.otx = OTXv2(OTX_KEY)

    def get_iocs_last(self):
        self.events = self.otx.getall()

    def getQuarter(self, date_time):
        d = str(date_time)
        year = date_time.split('-')[0]
        quarter = '1'
        m = date_time.split('-')[1]
        if m=='04' or m=='05' or m=='06':
            quarter = '2'
        if m=='07' or m=='08' or m=='09':
            quarter = '3'
        if m=='10' or m=='11' or m=='12':
            quarter = '4'
        return year + '-Q' + quarter
        

    def write_iocs(self):

        print 'Type,Value,PulseID,DateQuarter'

        for event in self.events:
            try:
                pulse_id = event['id']
                pulse_created = self.getQuarter(event['created'])

                for reference in event['references']:
                    vendor = tldextract.extract(reference).registered_domain

                    if len(vendor) > 3:
                        print 'Vendor,' + vendor + ',' + pulse_id + ',' + pulse_created
                    
                for country in event['targeted_countries']:
                    print 'Country,' + country.replace(',','') + ',' + pulse_id + ',' + pulse_created

                for industry in event['industries']:
                    print 'Industry,' + industry + ',' + pulse_id + ',' + pulse_created

                if event['adversary']:
                    if len( event['adversary'] ) > 0:
                        print 'Adversary,' + event['adversary'] + ',' + pulse_id + ',' + pulse_created

                for indicator in event['indicators']:
                    if indicator['type'] == 'CVE':
                            print indicator['type'] + ',' + indicator['indicator'] + ',' + pulse_id + ',' + pulse_created

            except Exception, e:
                traceback.print_exc()

def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)


if __name__ == '__main__':

    # Create a receiver
    otx_receiver = OTXReceiver()

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_iocs()