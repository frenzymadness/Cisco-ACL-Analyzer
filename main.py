import web
import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__))) 
from lib import *

# Root dir and render object with templates
rootdir = os.path.abspath(os.path.dirname(__file__)) + '/'
render = web.template.render(rootdir + 'templates/')

urls = (
    '/', 'index',
    '/result', 'result'
    )


# Main page
class index:
    def GET(self):
        return render.index()


class result:
    def POST(self):
        input = web.input()
        try:
            acl = ACL(input['acl'].split('\n'))
        except Exception as e:
            return e
        packet = Packet(input['protocol'], input['srcIP'], input['srcPort'], input['dstIP'], input['dstPort'])
        result = acl.check_packet(packet)
        print packet
        return render.result(result)


app = web.application(urls, globals(), autoreload=True)
application = app.wsgifunc()

