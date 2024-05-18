"""View specific host."""
from censys.search import CensysHosts, CensysCerts
from pprint import pprint
from datetime import datetime
from dotenv import load_dotenv
import time
import os
import json
import requests
import pydig
import whois
import google.generativeai as genai
import validators

class NVDApi:
    base_url = 'https://services.nvd.nist.gov/rest/json/'

    def __init__(self) -> None:
        self.key = os.getenv('NVD_API_KEY')
        self.max_results = 20
        self.timeout = 100
        self.delay = 0.6
        
    def get_cves_by_cpe_match_string(self, cpe):
        time.sleep(self.delay)
        url = f'{self.base_url}cves/2.0?cpeName={cpe}&resultsPerPage={self.max_results}'
        print(f'searching cve: {url}')
        cves = []
        try:
            res = requests.get(url, headers={'apiKey': self.key}, timeout=self.timeout)
            res = res.json()
            for cve in res['vulnerabilities']:
                cves.append({
                    'id': cve['cve']['id'], 
                    'description': cve['cve']['descriptions'][0]['value'], 
                    'url': 'https://nvd.nist.gov/vuln/detail/{}'.format(cve['cve']['id'])
                })
        except Exception as e:
            print(e)
            pass
        
        return cves

    def get_valid_cpes(self, cpe_str):
        time.sleep(self.delay)
        url = f'{self.base_url}cpematch/2.0?matchStringSearch={cpe_str}&resultsPerPage={self.max_results}'
        print(f'searching cpe: {url}')
        cpes = []
        try:
            res = requests.get(url, headers={'apiKey': self.key}, timeout=self.timeout)
            res = res.json()
            lt5 = False

            # get the first 5 cpes
            for cpe in res['matchStrings']:
                for match in cpe['matchString']['matches']:
                    if match['cpeName'] not in cpes:
                        cpes.append(match['cpeName'])
                    if len(cpes) >= 5:
                        lt5 = True
                        break
                if lt5:
                    break

        except Exception as e:
            print(e)
            pass

        if len(cpes) == 0:
            cpes.append(cpe_str)

        return cpes
        
class DomainWeaknessAnalysis:
    def __init__(self, domain: str):
        genai.configure(api_key=os.environ['GENMINI_API_KEY'])
        
        if validators.domain(domain):
            self.ips = pydig.query(domain, 'A')
        elif validators.ipv4(domain) or validators.ipv6(domain):
            self.ips = [domain]
            
        self.domain = domain
        self.c = CensysCerts()
        self.h = CensysHosts()
        self.nvd_api = NVDApi()
        self.model = genai.GenerativeModel(model_name='gemini-1.0-pro')

    def remove_outdated_certs(self, certs):
        valid_certs = []
        for cert in certs:
            start = cert["parsed"]["validity_period"]["not_before"]
            end = cert["parsed"]["validity_period"]["not_after"]

            if start and end:
                start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
                end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
                if start < datetime.now() < end:
                    valid_certs.append(cert)

        return valid_certs

    def get_whois(self):
        data = whois.whois(self.domain)

        idx = 0
        if 'domain_name' in data and isinstance(data['domain_name'], list):
            idx = data['domain_name'].index(self.domain) if self.domain in data['domain_name'] else 0
            del data['domain_name']
            
        possible_list = ['updated_date', 'creation_date', 'expiration_date', 'org', 'admin', 'address',
                            'admin_city', 'admin_email', 'admin_id', 'admin_phone', 'admin_postal_code', 'admin_org', 
                            'admin_state_province', 'admin_street', 'registrant_city', 'registrant_email', 
                            'registrant_id', 'registrant_name', 'registrant_organization', 'registrant_org' 'registrant_phone',
                            'registrant_postal_code', 'registrant_state_province', 'registrant_street',
                            'tech_city', 'tech_country', 'tech_email', 'tech_id', 'tech_name', 'tech_organization',
                            'tech_phone', 'tech_postal_code', 'tech_state_province', 'tech_street', 'tech_org']

        for key in possible_list:
            if key in data and isinstance(data[key], list):
                data[key] = data[key][idx]

        return data

    def get_certs_by_name(self):
        return self.c.search("names: {}".format(self.domain))()

    def get_hosts_data(self):
        query_str = f"ip: {{{', '.join(self.ips)}}}"
        hosts = self.h.search(query_str).view_all()

        services = self.get_services_vulns(hosts)
        
        ret = dict()

        for ip in self.ips:
            ret[ip] = {
                'location': hosts[ip]['location'],
                'autonomous_system': hosts[ip]['autonomous_system'],
                'services': services[ip]
            }

        return ret        
    
    def get_services_vulns(self, hosts):
        services = dict()
        recorded_raw_cpes = dict()
        recorded_valid_cpes = dict()
        
        for ip, host in hosts.items():
            if 'services' not in host:
                continue

            services[ip] = list()
            for service in host['services']:
                port_services = {'port': service['port'], 'transport_protocol': service['transport_protocol'], 
                                 'softwares': list(), 'vulns': list()}

                if 'software' not in service:
                    services[ip].append(port_services)
                    continue
                
                for software in service['software']:
                    raw_cpe = software['uniform_resource_identifier']

                    # check if the cpes are already recorded
                    if raw_cpe in recorded_raw_cpes:
                        cpe_strs = recorded_raw_cpes[raw_cpe]
                    else:
                        cpe_strs = self.nvd_api.get_valid_cpes(raw_cpe)
                        recorded_raw_cpes[raw_cpe] = cpe_strs

                    port_services['softwares'] += cpe_strs

                    for cpe_str in cpe_strs:
                        if cpe_str in recorded_valid_cpes:
                            port_services['vulns'] += recorded_valid_cpes[cpe_str]
                            continue
                    
                        cves = self.nvd_api.get_cves_by_cpe_match_string(cpe_str)
                        recorded_valid_cpes[cpe_str] = cves
                        port_services['vulns'] += cves

                services[ip].append(port_services)
                    
        return services

    
    def parse(self):
        whois_data = self.get_whois()
        
        certs = self.get_certs_by_name()
        certs = self.remove_outdated_certs(certs)

        hosts = self.get_hosts_data()
        
        result = {
            "name": self.domain,
            "whois_data": whois_data,
            "hosts": hosts,
            "valid certs": certs,
        }
        pprint(result)
        
        return result

    def get_summary(self, data):
        prompt = f"""You are a security analyst and you are tasked to analyze the security of the domain {self.domain}.
        You have access to the following json data: \n{data}
        Please provide a summary of the data in a consise manner, 
        the output contains three section: whois data summary, vulnerability analysis, and possible solutions sections, 
        only these section are allowed. 
        The title should be h3 and the content should be in bullet points.
        Please write in John Gruber’s Markdown format."""

        response = self.model.generate_content(prompt, safety_settings={
                'HATE': 'BLOCK_NONE',
                'HARASSMENT': 'BLOCK_NONE',
                'SEXUAL' : 'BLOCK_NONE',
                'DANGEROUS' : 'BLOCK_NONE'
            })
        return response.text


if __name__ == '__main__':
    load_dotenv()
    
    domain = input("domain name: ")

    result = DomainWeaknessAnalysis(domain)

    with open ("result.json", "w") as f:
        json.dump(result.parse(), f, indent=4, default=str)
