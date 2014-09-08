import web
import os
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
        acl = ACL(input['acl'].split('\n'))
        packet = Packet(input['protocol'], input['srcIP'], input['srcPort'], input['dstIP'], input['dstPort'])
        result = acl.check_packet(packet)
        print packet
        return render.result(result)


if __name__ == '__main__':
    app = web.application(urls, globals(), autoreload=True)
    app.run()
