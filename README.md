# Domain Weakness Passive Scanning System PoC
## Description
Scanning for Domain Weaknesses In this exercise, our goal is to passively identify weakness for a specified domain or IP address. 
Please develop a system that conducts a passive scan of the domain to gather general information such as ASN, Abuse Contact, open ports, and certificates. Subsequently, analyze the collected data to summarize any security risks associated with the domain. 
Please note that only passive scanning methods are permitted, which means using third-party data or accessing information legally without sending exploits or probes. 

Input: Provide a domain or IP address 
Output: 
1. General information obtained 
2. Identified security risks or weaknesses

## Solution
I took research on the 3rd party tools that can be used for passive scanning of the domain. I found that the following tools can be used for passive scanning of the domain:
1. [Shodan](https://www.shodan.io/) (Require payment)
2. [Censys](https://censys.io/)
3. [NIST NVD api](https://nvd.nist.gov/developers)
4. [python-whois](https://pypi.org/project/python-whois/)

I also utilized the Generative AI model - [Gemini](https://ai.google.dev/?gad_source=1&gclid=Cj0KCQjwgJyyBhCGARIsAK8LVLMiK2p9kOUo0AwatA-Xvficr9kW1RqwAfI8ke_XNFb0DCm2UEimX2saAsa2EALw_wcB) to summarize the parsed information and security risks or weaknesses.

This system is a web application developed using Flask.
The process of this system is as follows:
1. Accept the domain name or IP address from the user.
2. Use `pydig` to get the hosts binding with the domain.
3. Use `python-whois` to get the whois information of the domain.
4. Use Censys python sdk to get the information of the hosts.
5. Iterate each hosts, cross reference the information with the NIST NVD api to get the possible vulnerabilities.
6. Concate the information above and use Gemini to summarize the parsed information and security risks or weaknesses.
7. Return the summarized information to the user.

## How to run
*Requirements: Docker, Python 3.10, [Censys API key](https://search.censys.io/register), [Nvd api key](https://nvd.nist.gov/developers/request-an-api-key), [Gemini API key](https://ai.google.dev/?gad_source=1&gclid=Cj0KCQjwgJyyBhCGARIsAK8LVLOlpEr3oAPaNJhCUU1cYGIuVxKHNFBegGTWuw2anLw3QLYl9nzVGO4aAj4oEALw_wcB#develop-with-gemini)*  
*Censys api have 250 search quota a month for free plan*

1. Configure the API keys in the `.env` file.
```bash
cp .env.example .env
```
2. Execute the docker container
```bash
docker compose up -d
```
3. The system will run on localhost:5000