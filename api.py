#!/usr/bin/python

import BaseHTTPServer
import os
from subprocess import Popen, PIPE


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

        return (nsupdate.returncode == 0, nsupdate_data[0], nsupdate_data[1])

    def do_POST(self):
        """Respond to a POST request."""
        self.send_header("Content-type", "text/plain")
        update_result = self.update_name(self.client_address[0], os.path.basename(self.path))
        if update_result[0]:
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Update succesful\n")
            self.wfile.write(self.path)
            self.wfile.write(" -> ")
            self.wfile.write(self.client_address[0])
        else:
            self.send_response(502)
            self.end_headers()
            self.wfile.write("Update failed\n")
            self.wfile.write(update_result[2])


if __name__ == '__main__':
    httpd = BaseHTTPServer.HTTPServer(('', 8080), DnsUpdateApiHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
