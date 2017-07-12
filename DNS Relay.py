# Using python3
import socketserver
import struct
import socket

# DNS Query
class SinDNSQuery:
    def __init__(self, data):
        i = 1
        self.name = ''
        while True:
            d = data[i]
            if d == 0:
                break;
            if d < 32:
                self.name = self.name + '.'
            else:
                self.name = self.name + chr(d)
            i = i + 1
        self.querybytes = data[0:i + 1]
        (self.type, self.classify) = struct.unpack('>HH', data[i + 1:i + 5])
        self.len = i + 5

    def getbytes(self):
        return self.querybytes + struct.pack('>HH', self.type, self.classify)


# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS 
class SinDNSAnswer:
    def __init__(self, ip):
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.timetolive = 190
        self.datalength = 4
        self.ip = ip

    def getbytes(self):
        res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
        s = self.ip.split('.')
        res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return res


# DNS frame
# must initialized by a DNS query frame
class SinDNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH',data[0:12])
        self.query = SinDNSQuery(data[12:])

    def getname(self):
        return self.query.name

    def setip(self, ip):
        self.answer = SinDNSAnswer(ip)
        self.answers = 1
        self.flags = 33152

    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
        res = res + self.query.getbytes()
        if self.answers != 0:
            res = res + self.answer.getbytes()
        return res


# A UDPHandler to handle DNS query
class SinDNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        # print(data)
        dns = SinDNSFrame(data)
        sk = self.request[1]
        namemap = SinDNSServer.namemap
        # print(dns.query.type)
        if dns.query.type == 1:
            # If this is query a A record, then response it
            name = dns.getname()
            if namemap.__contains__(name):
                # If have record, response it
                dns.setip(namemap[name])
                if namemap[name] == '0.0.0.0':
                    # If the record is 0.0.0.0, block it
                    pass
                else:
                    sk.sendto(dns.getbytes(), self.client_address)
            else:
                # If not, re-transmit it
                sk2 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)
                sk2.sendto(data,('114.114.114.114', 53))
                tempdata = sk2.recvfrom(512)[0]
                # print(self.client_address)
                sk.sendto(tempdata, self.client_address)
        else:
            # If this is not query a A record, transimit it
            # sk.sendto(data, self.client_address)
            sk2 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)
            sk2.sendto(data,('114.114.114.114', 53))
            tempdata = sk2.recvfrom(512)[0]
            # print(self.client_address)
            sk.sendto(tempdata, self.client_address)


# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class SinDNSServer:
    def __init__(self, port=53):
        SinDNSServer.namemap = {}
        self.port = port

    def addname(self, name, ip):
        SinDNSServer.namemap[name] = ip

    def start(self):
        HOST, PORT = "127.0.0.1", self.port
        server = socketserver.UDPServer((HOST, PORT), SinDNSUDPHandler)
        server.serve_forever()


# Test it
# Read local database in file
if __name__ == "__main__":
    sev = SinDNSServer()

    txt = open("DNSHost.txt")
    for line in txt.readlines():
        sev.addname(line.split()[0], line.split()[1])
        # print(line.split()[0], line.split()[1])

    sev.start()
    
    """
    sev.addname('www.aa.com', '192.168.0.1')  # add a A record
    sev.addname('www.bb.com', '192.168.0.2')  # add a A record
    sev.addname('www.cc.com', '0.0.0.0')
    sev.addname('www.qq.com', '110.110.110.110')
    sev.addname('www.bupt.edu.cn', '123.123.123.123')
    sev.start()  # start DNS server
    """

# Now, U can use "nslookup" command to test it
# Such as "nslookup www.aa.com"
