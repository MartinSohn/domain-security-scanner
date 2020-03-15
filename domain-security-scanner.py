import requests
import socket
import ssl
from time import gmtime, strftime, strptime
from bs4 import BeautifulSoup
import json

# disable console warning after disabling validation of certificated
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Site:
    def __init__(self, domain):
        self.timestamp = strftime('%b %e %H:%M:%S %Y GMT', gmtime()) 
        self.domain = domain

        self.response = self.__scanSite('https') # send GET request to site, save response

        # HTTP response headers
        self.headerTypes = ['Server','Strict-Transport-Security', 'Public-Key-Pins', 'X-Content-Type-Options',
                        'X-XSS-Protection', 'X-Frame-Options', 'Content-Security-Policy',
                        'Content-Security-Policy-Report-Only'] # list of headers to test
        self.responseHeaders = {} # dict of test results
        for header in self.headerTypes: # get each header from response and save result
            self.responseHeaders[header] = self.__getResponseHeader(header)

        # HTML
        self.content = BeautifulSoup(self.response.content, 'html.parser') # parse html from response
        self.title = self.__getSiteTitle()
        
        # Get IP address of domain name
        self.ip = socket.gethostbyname(self.domain)

        # Certificate
        self.cert = self.__getCertificate() # get certificate for site
        self.certificate = {}
        if self.cert: # Check if a certificate was recieved
            # Save certificate details to dict
            certData = {}
            certData['subject'] = dict(x[0] for x in self.cert['subject'])
            certData['subjectAltName'] = [x[1] for x in self.cert['subjectAltName']]
            certData['serialNumber'] = self.cert['serialNumber']
            certData['notBefore'] = self.cert['notBefore']
            certData['notAfter'] = self.cert['notAfter']
            certData['csa'] = 'None' #TODO
            
            issuer = {}
            for value in self.cert['issuer']:
                issuer[value[0][0]] = value[0][1]
            certData['issuer'] = issuer
            self.certificate = certData

        # Test TLS protocols
        self.supportedTLSProtocols = self.__getSupportedTLSProtocols()
        self.supportedCiphers = self.__getSupportedCiphers()

    # return a printable representation of the site
    def __repr__(self):
        return "domain:'%s', title: '%s', server: '%s', date: '%s'" % (self.domain, self.title, self.server, self.date)

    # get site title
    def __getSiteTitle(self):
        if self.content.title:
            title = self.content.title.string # get site title

            # remove newline characters
            title = title.replace('\r','')
            title = title.replace('\n','')
        
            title = title.strip()  # remove leading and trailing whitespace
        else:
            title = None

        return title

    # scan the site
    def __scanSite(self, protocol):
        return (requests.get(url = protocol + '://' + self.domain, verify=False))

    def __getSupportedCiphers(self):
        supportedCiphers = {} # to store results of tested ciphers

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) # testing ciphers with TLSv1.2
        availableCiphers = context.get_ciphers() # get all available ciphers from ssl context

        # test each cipher
        for cipher in availableCiphers:
            try:
                context.set_ciphers(cipher['name']) # ssl context is forced to use the selected cipher
                try: # try to establish connection with cipher
                    with socket.create_connection((domain, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            result = True # site successfully uses the tested cipher
                    sock.close() # close connection
                except:
                    result = False  # site fails to use the tested cipher

                supportedCiphers[cipher['name']] = result # save result of the cipher test
            except:
                # happens most often if the ssl.SSLContext.set_ciphers fails
                # the tested cipher will not be included in the test results
                pass
        
        # return results of all tests
        return supportedCiphers

    def __getSupportedTLSProtocols(self):
        testTLSProtocols = {'TLSv1.0': ssl.PROTOCOL_TLSv1, 'TLSv1.1': ssl.PROTOCOL_TLSv1_1, 'TLSv1.2': ssl.PROTOCOL_TLSv1_2} # protocols to be tested
        supportedTLSProtocols = {} # to store results of tested protocols

        # test each protocol
        for protocol in testTLSProtocols:
            context = ssl.SSLContext(testTLSProtocols[protocol])
            # try to establish connection with protocol
            try:
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        result = True
                sock.close() # close connection
            except:
                result = False

            supportedTLSProtocols[protocol] = result
        return supportedTLSProtocols

    # get the sites domain certificate
    def __getCertificate(self):
        # create a default context with recommended settings
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=self.domain)

        try:
            s.connect((self.domain, 443))
        except:
            return None

        cert = s.getpeercert() # get certificate from established connection
        s.close() # close connection

        return cert

    # extract a response header from full HTTP response
    def __getResponseHeader(self, headerName):
        try:
            return self.response.headers[headerName]
        except:
            return None
    
    # Combine site data into dict and output as JSON string
    # indent:       Indentations of outputted JSON. 0 = disable indentation
    # ensure_ascii: https://docs.python.org/2/library/json.html#json.dumps "If ensure_ascii is true (the default), all non-ASCII characters in the output are escaped with \uXXXX sequences, and the results are str instances consisting of ASCII characters only. If ensure_ascii is false, a result may be a unicode instance. This usually happens if the input contains unicode strings or the encoding parameter is used."
    def toJson(self, indent, ensure_ascii):
        data = {}
        data['domain'] = self.domain
        data['timestamp'] = self.timestamp
        data['ip'] = self.ip
        data['title'] = self.title
        data['headers'] = self.responseHeaders

        cryptoData = {}
        cryptoData['certificate'] = self.certificate
        cryptoData['tlsProtocol'] = self.supportedTLSProtocols
        cryptoData['cipher'] = self.supportedCiphers
        data['cryptography'] = cryptoData

        # print site as JSON to console
        if indent: # Check 'indent' value. Disable if 0
            print(json.dumps(data, indent=indent, ensure_ascii=ensure_ascii))
        else:
            print(json.dumps(data))

        # return site JSON object
        return data
        
filename = "domains.txt" # filename of domains to be imported
filename_output = "output.json" # filename of JSON file to export results to

# read domains from file
with open(filename) as f:
	domains = [line.rstrip('\n') for line in f]
f.close()

jsonData = {} # dictionary to store all sites

# scan all domains
for domain in domains:
    # ignore all domains in file after '#'
    if domain == '#':
        break

    # TODO here we should remove http(s):// from each domain
    # TODO here we should do a regex validation of each domain

    # create site object
    try:
        site = Site(domain)
    except: # skip site if it fails
        print("Warning: scan failed of %s" % (domain))
        continue

    # save site to dictionary of sites, and print it to console
    jsonData[domains.index(domain)] = site.toJson(3, False)

# output all sites to file
with open(filename_output, 'w') as outfile:
    json.dump(jsonData, outfile)