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

    def check_channel_exec_request(self, channel, command):
        print(f'exec {channel} @ {command}')
        return False

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


class ChannelCtx():
    c: paramiko.Channel

    def __init__(self, chan: paramiko.Channel):
        if chan is None:
            raise RuntimeError("No channel")
        self.c = chan

    def __enter__(self):
        return self.c
    
    def __exit__(self, *args):
        self.c.close()

def stuff(known_hosts):
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 2200))

    sock.listen(100)
    print("Listening for connection ...")
    client, addr = sock.accept()

    print("Got a connection!")

    with paramiko.Transport(client) as t:
        t.add_server_key(host_key)
        server = Server(known_hosts)
        t.start_server(server=server)

        with ChannelCtx(t.accept(20)) as chan:
            print("Authenticated!")

            server.event.wait(10)
            if not server.event.is_set():
                print("*** Client never asked for a shell.")
                raise

            chan.send("Username: ")
            f = chan.makefile("rU")
            username = f.readline().strip("\r\n")
            chan.send(f"\r\nReceived: {username}\r\n")

def test_ssh(caplog):
    caplog.set_level(logging.INFO)
    print(f"Read key: {hexlify(host_key.get_fingerprint())}")
    with importlib.resources.path("tests", "ed25519_au_ke") as keypath:
        known_hosts = paramiko.HostKeys(filename=str(keypath))
    assert "Not enough fields found" not in caplog.text
    stuff(known_hosts=known_hosts)
    assert 0
