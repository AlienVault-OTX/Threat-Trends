# Lists out products targetted by CVE

import requests, json

with open("cves.txt") as file:
    lines = file.readlines()

    for line in lines:
        

        try: 
            cve = line.strip()


            result =  requests.get('https://otx.alienvault.com/otxapi/indicator/cve/' + cve)
            j = json.loads(result.text)

            print '\n\n' + cve
            print j['products']
        except Exception as ex:
            print str(ex)
