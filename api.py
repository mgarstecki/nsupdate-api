#!/usr/bin/python

import BaseHTTPServer
import os
import sys
import json
import re
import logging

from subprocess import Popen, PIPE
from netaddr import IPAddress, IPNetwork

# For a string in the format ftXYZ-aaaa10toto, extract ftXYZ
PREFIX_REGEX_PATTERN = '^(ft\w+)-.+'

prefixToNetwork = {}
noPrefixNetwork = None
prefixRegex = re.compile(PREFIX_REGEX_PATTERN, re.IGNORECASE)
logger = None

class UpdateRejectedError(Exception):
    pass

class UpdateFailedError(Exception):
    def __init__(self, message, stderr):
        super(UpdateFailedError, self).__init__(message)
        self.stderr = stderr

class DnsUpdateApiHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def update_name(self, ip, name):
        update_input="""
        update delete %(name)s.%(zone)s. A
        update add %(name)s.%(zone)s. 600 A %(ip)s
        send
        """ % {"zone": "archinext.local", "name": name, "ip": ip}

        print update_input

        nsupdate = Popen(["nsupdate", "-l"], stdout=PIPE, stdin=PIPE, stderr=PIPE)
        nsupdate_data = nsupdate.communicate(input=update_input)

        if nsupdate.returncode != 0:
            raise UpdateFailedError("The update failed", nsupdate_data[1])

    def get_name_prefix(self, name):
        match = prefixRegex.match(name)
        if match:
            return match.group(1)
        else:
            raise UpdateRejectedError("No valid team prefix was found in hostname")

    def accept_update(self, ip, name):
        parsedIp = IPAddress(ip)
        if parsedIp in noPrefixNetwork:
            return

        namePrefix = self.get_name_prefix(name).lower()

        if not namePrefix in prefixToNetwork:
            raise UpdateRejectedError("Unknown team prefix " + namePrefix)

        networkForPrefix = prefixToNetwork[namePrefix]
        if not networkForPrefix:
            raise UpdateRejectedError("No valid network found for the team prefix " + namePrefix)

        if parsedIp not in networkForPrefix:
            raise UpdateRejectedError("This host is not in the allowed network for the team prefix " + namePrefix)

    def log_failure(self, exception):
        logger.debug("Update failed for " + self.client_address[0] + " on " + self.path + ", error:")
        logger.exception(exception)

    def do_POST(self):
        """Respond to a POST request."""
        self.send_header("Content-type", "text/plain")

        shortHostname = os.path.basename(self.path)
        print shortHostname
        try:
            self.accept_update(self.client_address[0], shortHostname)
            self.update_name(self.client_address[0], shortHostname)
        except UpdateRejectedError as e:
            self.log_failure(e)
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Update request rejected.\n")
            self.wfile.write("Reason: " + e.args[0])
        except UpdateFailedError as e:
            self.log_failure(e)
            self.send_response(502)
            self.end_headers()
            self.wfile.write("Update request failed.\n")
            self.wfile.write("Error log:\n")
            self.wfile.write(e.stderr)
        except Exception as e:
            self.log_failure(e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write("An unexpected error has occured.\n")
            self.wfile.write("Error message: " + e.args[0])
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Update succesful\n")
            self.wfile.write(shortHostname)
            self.wfile.write(" -> ")
            self.wfile.write(self.client_address[0])

def load_config():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: " + sys.argv[0] + " config-file-path")
        sys.exit(1)

    with open(sys.argv[1], 'r') as confStream:
        return json.load(confStream)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    config = load_config()

    for prefix,ipnet in config['prefixes'].iteritems():
        prefixToNetwork[prefix.lower()] = IPNetwork(ipnet)

    noPrefixNetwork = IPNetwork(config['noPrefixNetwork'])

    logger.debug("Parsed configuration:")
    logger.debug("  Prefixless network: " + noPrefixNetwork.__str__())
    logger.debug("  Prefixed networks:")
    for prefix,ipnet in prefixToNetwork.iteritems():
        logger.debug("    " + prefix + ": " + ipnet.__str__())

    httpd = BaseHTTPServer.HTTPServer(('', 8080), DnsUpdateApiHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
