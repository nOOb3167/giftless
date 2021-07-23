from __future__ import annotations
import asyncio
import asyncio.futures
import contextlib
import contextvars
import dataclasses
import io
import logging
import paramiko
import typing

# grrrr module only defines these flags on linux
try:
    from socket import SOCK_CLOEXEC, SOCK_NONBLOCK
except Exception:
    SOCK_CLOEXEC = 0
    SOCK_NONBLOCK = 0


T = typing.TypeVar('T')
ResuT = typing.TypeVar('ResuT', bound='ResurrectableTask')
DataT = typing.Union[bytes, 'Eof']

ctx_conid_var: contextvars.ContextVar[int] = contextvars.ContextVar('conid', default=-1)


class Eof:
    def __len__(self):
        return 0


@dataclasses.dataclass
class Addr:
    host: str
    port: int


@dataclasses.dataclass
class ExcChain:
    e: typing.Optional[Exception]

    @contextlib.contextmanager        
    def thrower(self):
        yield self
        if self.e is not None:
            raise RuntimeError('Exception Chain') from self.e
    
    @contextlib.contextmanager
    def chainer(self):
        try:
            yield
        except Exception as e:
            try:
                raise e from self.e
            except Exception as e_:
                self.e = e_


async def as_completed(fs):
    assert all([asyncio.futures.isfuture(x) for x in fs])
    pending = fs
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for d in done:
            yield d


@contextlib.asynccontextmanager
async def task_awaiter(a: typing.Iterable[asyncio.Task]):
    try:
        yield
    finally:
        with ExcChain(None).thrower() as ec:
            for i in a:
                with ec.chainer():
                    await i


@contextlib.asynccontextmanager
async def queue_get(b: asyncio.Queue[T]) -> typing.AsyncIterator[T]:
    i = await b.get()
    try:
        yield i
    finally:
        b.task_done()


@contextlib.contextmanager
def ctx_conid(conid: int) -> typing.Iterator[None]:
    token = ctx_conid_var.set(conid)
    try:
        yield
    finally:
        ctx_conid_var.reset(token)


@contextlib.contextmanager
def ctx_channel(t: paramiko.Transport, accept_timeout: typing.Optional[float]) -> typing.Iterator[paramiko.Channel]:
    with t.accept(accept_timeout) or contextlib.nullcontext() as chan:
        if chan is None:
            raise RuntimeError('Channel Accept Timeout')
        yield chan


class ConIdLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f'''[conid={ctx_conid_var.get()}] {msg}''', kwargs


class ResurrectableTask:
    task: asyncio.Task

    def __init__(self):
        self.task = typing.cast(asyncio.Task, None)

    def done(self) -> bool:
        return self.task is None or self.task.done()

    def ensure_done(self) -> ResurrectableTask:
        if not self.done():
            raise RuntimeError()
        return self

    @contextlib.contextmanager
    def with_resurrect_check(self):
        if not self.done():
            raise RuntimeError()
        try:
            yield
        finally:
            if self.done():
                raise RuntimeError()

    @contextlib.contextmanager
    def with_try_take(self: typing.Optional[T], s: set[ResuT]) -> typing.Iterator[typing.Optional[T]]:
        if self in s:
            try:
                yield self
            finally:
                s.remove(typing.cast(ResuT, self))
        else:
            yield None


@dataclasses.dataclass
class Done(typing.Generic[ResuT]):
    tasks: set[asyncio.Task]
    resus: set[ResuT]


class Waiter(typing.Generic[ResuT]):
    tasks: set[asyncio.Task]
    resus: set[ResuT]

    def __init__(self, *resus: ResuT):
        self.tasks = set[asyncio.Task]()
        self.resus = {x for x in resus}

    def add_task(self, task: asyncio.Task):
        self.tasks.add(task)

    @contextlib.contextmanager
    def needing_resurrect(self) -> typing.Iterator[set[ResuT]]:
        nr = {x for x in self.resus if x.done()}
        try:
            yield nr
        finally:
            if len(nr):
                raise RuntimeError()

    @contextlib.asynccontextmanager
    async def wait(self) -> typing.AsyncIterator[Done[ResuT]]:
        resus_dict = {x.task: x for x in self.resus}
        wait = [x for x in self.tasks] + [x.task for x in self.resus]
        done, pending = await asyncio.wait(wait, return_when=asyncio.FIRST_COMPLETED)
        resus_done = set()
        tasks_done = set()
        for x in done:
            if x in resus_dict:
                resus_done.add(resus_dict[x].ensure_done())
            else:
                tasks_done.add(x)
        yield Done[ResuT](tasks=tasks_done, resus=resus_done)


def pkey_from_str(s: str):
    with io.StringIO(s) as f:
        return paramiko.Ed25519Key(file_obj=f)
