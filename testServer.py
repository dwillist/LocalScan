import socketserver

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        print("{} connected".format(self.client_address[0]))
        self.data = self.request.recv(1024).strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)


HOST, PORT = '192.168.1.197', 9998

# Create the server, binding to localhost on port 9999
def create_server():
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
        server.serve_forever()