import logging
import aio_etcd
import uuid
import asyncio

_log = logging.getLogger(__name__)

class Lock(object):
    """
    Locking recipe for etcd, inspired by the kazoo recipe for zookeeper
    """

    def __init__(self, client, lock_name):
        self.client = client
        self.name = lock_name
        # props to Netflix Curator for this trick. It is possible for our
        # create request to succeed on the server, but for a failure to
        # prevent us from getting back the full path name. We prefix our
        # lock name with a uuid and can check for its presence on retry.
        self._uuid = uuid.uuid4().hex
        self.path = "/_locks/{}".format(lock_name)
        self.is_taken = False
        self._sequence = None
        _log.debug("Initiating lock for %s with uuid %s", self.path, self._uuid)

    @property
    def uuid(self):
        """
        The unique id of the lock
        """
        return self._uuid

    async def set_uuid(self, value):
        old_uuid = self._uuid
        self._uuid = value
        if not (await self._find_lock()):
            _log.warn("The hand-set uuid was not found, refusing")
            self._uuid = old_uuid
            raise ValueError("Nonexistent UUID")

    async def is_acquired(self):
        """
        tells us if the lock is acquired
        """
        if not self.is_taken:
            _log.debug("Lock not taken")
            return False
        try:
            await self.client.read(self.lock_key)
            return True
        except aio_etcd.EtcdKeyNotFound:
            _log.warn("Lock was supposedly taken, but we cannot find it")
            self.is_taken = False
            return False

    async def acquire(self, blocking=True, lock_ttl=3600):
        """
        Acquire the lock.

        :param blocking Block until the lock is obtained, or timeout is reached
        :param lock_ttl The duration of the lock we acquired, set to None for eternal locks
        :param timeout The time to wait before giving up on getting a lock
        """
        # First of all try to write, if our lock is not present.
        if not (await self._find_lock()):
            _log.debug("Lock not found, writing it to %s", self.path)
            res = await self.client.write(self.path, self.uuid, ttl=lock_ttl, append=True)
            self._set_sequence(res.key)
            _log.debug("Lock key %s written, sequence is %s", res.key, self._sequence)
        elif lock_ttl:
            # Renew our lock if already here!
            await self.client.write(self.lock_key, self.uuid, ttl=lock_ttl)

        # now get the owner of the lock, and the next lowest sequence
        return self._acquired(blocking=blocking)

    async def release(self):
        """
        Release the lock
        """
        if not self._sequence:
            await self._find_lock()
        try:
            _log.debug("Releasing existing lock %s", self.lock_key)
            await self.client.delete(self.lock_key)
        except aio_etcd.EtcdKeyNotFound:
            _log.info("Lock %s not found, nothing to release", self.lock_key)
            pass
        finally:
            self.is_taken = False

    async def __aenter__(self):
        """
        You can use the lock as a contextmanager
        """
        await self.acquire(blocking=True, lock_ttl=0)

    async def __aexit__(self, type, value, traceback):
        await self.release()

    async def _acquired(self, blocking=True):
        locker, nearest = await self._get_locker()
        self.is_taken = False
        if self.lock_key == locker:
            _log.debug("Lock acquired!")
            # We own the lock, yay!
            self.is_taken = True
            return True
        else:
            self.is_taken = False
            if not blocking:
                return False
            # Let's look for the lock
            watch_key = nearest
            _log.debug("Lock not acquired, now watching %s", watch_key)
            while True:
                try:
                    r = await self.client.watch(watch_key)
                    _log.debug("Detected variation for %s: %s", r.key, r.action)
                    return (await self._acquired(blocking=True))
                except aio_etcd.EtcdKeyNotFound:
                    _log.debug("Key %s not present anymore, moving on", watch_key)
                    return (await self._acquired(blocking=True))
                except aio_etcd.EtcdException:
                    # TODO: log something...
                    pass

    @property
    def lock_key(self):
        if not self._sequence:
            raise ValueError("No sequence present.")
        return self.path + '/' + str(self._sequence)

    def _set_sequence(self, key):
        self._sequence = key.replace(self.path, '').lstrip('/')

    async def _find_lock(self):
        if self._sequence:
            try:
                res = await self.client.read(self.lock_key)
                self._uuid = res.value
                return True
            except aio_etcd.EtcdKeyNotFound:
                return False
        elif self._uuid:
            try:
                for r in (await self.client.read(self.path, recursive=True)).leaves:
                    if r.value == self._uuid:
                        self._set_sequence(r.key)
                        return True
            except aio_etcd.EtcdKeyNotFound:
                pass
        return False

    async def _get_locker(self):
        results = [res for res in
                   (await self.client.read(self.path, recursive=True)).leaves]
        if not self._sequence:
            await self._find_lock()
        l = sorted([r.key for r in results])
        _log.debug("Lock keys found: %s", l)
        try:
            i = l.index(self.lock_key)
            if i == 0:
                _log.debug("No key before our one, we are the locker")
                return (l[0], None)
            else:
                _log.debug("Locker: %s, key to watch: %s", l[0], l[i-1])
                return (l[0], l[i-1])
        except ValueError as exc:
            # Something very wrong is going on, most probably
            # our lock has expired
            raise aio_etcd.EtcdLockExpired(u"Lock not found") from exc
