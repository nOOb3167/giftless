import importlib.resources
import logging
import paramiko
import socket
import threading
from binascii import hexlify

with importlib.resources.path("tests", "ed25519_00.key") as keypath:
    host_key = paramiko.Ed25519Key(filename=str(keypath))

class Server(paramiko.ServerInterface):
    def __init__(self, known_hosts):
        self.known_hosts = known_hosts
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        print(f"Auth attempt with key: {hexlify(key.get_fingerprint())}")
        if (username == "robey") and self.known_hosts.check("giftless.example", key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def stuff(known_hosts):
    DoGSSAPIKeyExchange = True

    # now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 2200))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        raise

    try:
        sock.listen(100)
        print("Listening for connection ...")
        client, addr = sock.accept()
    except Exception as e:
        print("*** Listen/accept failed: " + str(e))
        raise

    print("Got a connection!")

    try:
        t = paramiko.Transport(client)
        t.add_server_key(host_key)
        server = Server(known_hosts)
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("*** SSH negotiation failed.")
            raise

        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            raise
        print("Authenticated!")

        server.event.wait(10)
        if not server.event.is_set():
            print("*** Client never asked for a shell.")
            raise

        chan.send("\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n")
        chan.send(
            "We are on fire all the time!  Hooray!  Candy corn for everyone!\r\n"
        )
        chan.send("Happy birthday to Robot Dave!\r\n\r\n")
        chan.send("Username: ")
        f = chan.makefile("rU")
        username = f.readline().strip("\r\n")
        chan.send("\r\nI don't like you, " + username + ".\r\n")
        chan.close()

    finally:
        t.close()

def test_ssh(caplog):
    caplog.set_level(logging.INFO)
    print(f"Read key: {hexlify(host_key.get_fingerprint())}")
    with importlib.resources.path("tests", "ed25519_au_ke") as keypath:
        known_hosts = paramiko.HostKeys(filename=str(keypath))
    assert "Not enough fields found" not in caplog.text
    stuff(known_hosts=known_hosts)
    assert 0
