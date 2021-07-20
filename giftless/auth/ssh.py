import asyncio
import contextlib
import contextvars
import collections
import functools
import io
import logging
import paramiko
import socket
import typing


# grrrr only defined in module on linux
try:
    from socket import SOCK_CLOEXEC, SOCK_NONBLOCK
except Exception:
    SOCK_CLOEXEC = 0
    SOCK_NONBLOCK = 0


server_private_key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE1Ja6z82m/tNfmbk8sQAA
AKAsaDjeLGg43gAAAAtzc2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE
1Ja6z82m/tNfmbk8sQAAAEByvVNWu+C19TiL6NvLle+rAzRPeLNmlJ4iRKVu28UQ
ccj28uKt58Zh+2NbZPAy8ezTe8TUlrrPzab+01+ZuTyxAAAADmVkMjU1MTkta2V5
LTAwAQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH PRIVATE KEY-----
'''


ctx_conid = contextvars.ContextVar('conid', default=None)


class CtxAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f'''[conid={ctx_conid.get('root')}] {msg}''', kwargs


@contextlib.contextmanager
def with_ctx_conid(conid: int):
    token = ctx_conid.set(conid)
    try:
        yield
    finally:
        ctx_conid.reset(token)


log = CtxAdapter(logging.getLogger(__name__), extra={})

Addr = collections.namedtuple('Addr', ['host', 'port'])


def pkey_from_str(s: str):
    with io.StringIO(s) as f:
        return paramiko.Ed25519Key(file_obj=f)


class FutureEvent:
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future

    def __init__(self, loop: asyncio.AbstractEventLoop, future: asyncio.Future):
        self.loop = loop
        self.future = future
    
    def set(self):
        self.loop.call_soon_threadsafe(self.future.set_result, None)


class AsyncServ:
    CHANNEL_ACCEPT_TIMEOUT = 120
    loop: asyncio.AbstractEventLoop
    sock: socket.socket
    server_key: paramiko.PKey

    def __init__(self, sock: socket.socket, server_key: paramiko.PKey):
        self.loop = asyncio.new_event_loop()
        self.sock = sock
        self.server_key = server_key

    def run_until_complete(self):
        self.loop.run_until_complete(self.start_())

    async def start_(self):
        conid: int = 0
        accept: typing.Optional[asyncio.Task] = None
        wait: set[asyncio.Task] = set()
        log.info(f'Starting to accept connections')
        while True:
            wait |= {(accept := accept or loop().create_task(loop().sock_accept(self.sock)))}
            done, pending = await asyncio.wait(wait, return_when=asyncio.FIRST_COMPLETED)
            for d in done:
                await d
            wait = pending
            if accept in done:
                nsock, addr = accept.result()
                log.info(f'Connected from address: {addr}')
                with with_ctx_conid((conid := conid + 1)):
                    wait |= {loop().create_task(self.start_con(nsock))}
                accept = None

    async def cb_auth_publickey(self, username: str, key: paramiko.PKey):
        log.info(f'auth_publickey')

    async def cb_exec_request_pre(self, command_future: asyncio.Future, channel: paramiko.Channel, command: str):
        command_future.set_result(command)
        log.info(f'exec_request_pre')
                
    async def start_con(self, nsock: socket.socket):
        set_nodelay(nsock)
        with paramiko.Transport(nsock) as t:
            protocol_negotiation_future = loop().create_future()
            command_future = loop().create_future()
            server = ServerX(
                loop=loop(),
                coro_auth_publickey=self.cb_auth_publickey,
                coro_exec_request_pre=functools.partial(self.cb_exec_request_pre, command_future))
            t.add_server_key(key=self.server_key)
            t.start_server(event=FutureEvent(loop(), protocol_negotiation_future), server=server)
            log.info(f'waiting for protocol negotiation')
            await protocol_negotiation_future
            logging.info(f'after_negotiation')
            command = await con_have_exec_future
            logging.info(f'after_have_exec')

            logging.info(f'command {command}')

            await sleep(0)

            with channel_ctx(t, self.CHANNEL_ACCEPT_TIMEOUT) as chan:
                crw = ChannelReadWaiter(chan)

                @contextlib.asynccontextmanager
                async def queue_get(b: asyncio.Queue):
                    i = await b.get()
                    try:
                        yield i
                    finally:
                        b.task_done()
                class Eof:
                    pass

                comOq, comEq, comIq = [asyncio.Queue() for x in range(3)]

                async def com_rd(sr: StreamReader, b: asyncio.Queue):
                    while True:
                        data = await sr.read(1024)
                        data = data if len(data) else Eof()
                        logging.info(f'com_rd {data}')
                        b.put_nowait(data)
                        if isinstance(data, Eof):
                            break
                async def com_wr(sw: StreamWriter, b: asyncio.Queue):
                    while True:
                        async with queue_get(b) as i:
                            logging.info(f'com_wr {i}')
                            if isinstance(i, Eof):
                                sw.write_eof()
                                await sw.wait_closed()
                                break
                            else:
                                sw.write(i)
                                await sw.drain()
                async def chan_rd(crw: ChannelReadWaiter, chan: paramiko.Channel, b: asyncio.Queue):
                    while True:
                        await crw.wait_read_a()
                        if chan.recv_stderr_ready():
                            raise RuntimeError('unexpected')
                        if chan.recv_ready():
                            data = r if len(r := chan.recv(X_BIG_ENUF)) else Eof()
                            b.put_nowait(data)
                            if isinstance(data, Eof):
                                break
                async def chan_wr(sendallfunc: Callable[[str], None], b: asyncio.Queue):
                    def wr(sendallfunc: Callable[[str], None], data: bytes):
                        sendallfunc(b'nothing')
                    async with queue_get(b) as i:
                        if isinstance(i, Eof):
                            pass
                        else:
                            await asyncio.to_thread(wr, sendallfunc, i)

                #proc = await create_subprocess_exec(R'C:\Program Files\Git\cmd\git.exe', 'log', '--', stdin=PIPE, stdout=PIPE, stderr=PIPE)
                proc = await create_subprocess_exec(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                # async def wx():
                #     logging.info('tttt')
                #     proc.stdin.write(b'yes')
                #     logging.info('tttt3')
                #     await proc.stdin.drain()
                #     logging.info('tttt2')
                #     proc.stdin.write_eof()
                # async def rx():
                #     data = proc.stdout.read(1024)
                #     logging.info('yyyy {data}')
                # await wx()
                # await com_rd(proc.stdout, comOq)
                # logging.info('past')
                rds = await gather(
                    com_rd(proc.stdout, comOq),
                    com_rd(proc.stderr, comEq),
                    com_wr(proc.stdin, comIq),
                    chan_rd(crw, chan, comIq),
                    asyncio.to_thread(chan_wr, chan.sendall),
                    asyncio.to_thread(chan_wr, chan.sendall_stderr),
                    proc.wait())

                logging.info(f'rds {rds}')
                #chan.send_exit_status(rds[_proc_])

            return

def loop():
    return asyncio.get_running_loop()

def set_nodelay(sock: socket.socket):
    """https://docs.python.org/3/library/asyncio-eventloop.html#:~:text=The%20socket%20option%20TCP_NODELAY%20is%20set%20by%20default
    FIXME: is this public API ? asyncio documentation hints on TCP_NODELAY being set by default"""
    from asyncio.base_events import _set_nodelay
    _set_nodelay(sock) # FIXME: is this public API ?


def sock_for_port_serv(port: int):
    for family, typ, proto, canonname, sockaddr in socket.getaddrinfo(None, port, family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=0, flags=socket.AI_PASSIVE | socket.AI_V4MAPPED | socket.AI_ADDRCONFIG):
        with contextlib.suppress(Exception), \
                contextlib.ExitStack() as es:
            es.enter_context(contextlib.closing(s := socket.socket(family, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, proto)))
            s.bind(sockaddr)
            s.listen(100)
            es.pop_all()
            return s
    raise RuntimeError(f'Listening on port {port}')


def start_server(sock: socket.socket):
    server_key: paramiko.Ed25519Key = pkey_from_str(server_private_key)
    serv = AsyncServ(sock, server_key)
    serv.run_until_complete()
