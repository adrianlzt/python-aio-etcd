from .test_simple import EtcdIntegrationTest
from aio_etcd import auth
import aio_etcd as etcd
from . import helpers

import asyncio
from pytest import raises

class TestEtcdAuthBase(EtcdIntegrationTest):
    cl_size = 1

    def setUp(self):
        # Sets up the root user, toggles auth
        loop = asyncio.get_event_loop()
        self.client = etcd.Client(port=6281, loop=loop)

        u = auth.EtcdUser(self.client, 'root')
        u.password = 'testpass'
        loop.run_until_complete(u.write())
        self.client = etcd.Client(port=6281, username='root',
                                password='testpass', loop=loop)
        self.unauth_client = etcd.Client(port=6281, loop=loop)
        a = auth.Auth(self.client)
        loop.run_until_complete(a.set_active(True))

    def tearDown(self):
        loop = asyncio.get_event_loop()

        u = auth.EtcdUser(self.client, 'test_user')
        r = auth.EtcdRole(self.client, 'test_role')
        try:
            loop.run_until_complete(u.delete())
        except:
            pass
        try:
            loop.run_until_complete(r.delete())
        except:
            pass
        a = auth.Auth(self.client)
        loop.run_until_complete(a.set_active(False))


class EtcdUserTest(TestEtcdAuthBase):
    @helpers.run_async
    def test_names(loop,self):
        u = auth.EtcdUser(self.client, 'test_user')
        self.assertEquals((yield from u.get_names()),[
            {
                'user': 'root',
                'roles': [{
                    'role': 'root', 'permissions': {
                        'kv': {'read': ['/*'], 'write': ['/*']}
                    }
                }]
            }
        ])

    @helpers.run_async
    def test_read(loop,self):
        u = auth.EtcdUser(self.client, 'root')
        # Reading an existing user succeeds
        try:
            yield from u.read()
        except Exception:
            self.fail("reading the root user raised an exception")

        # roles for said user are fetched
        self.assertEquals(u.roles, set(['root']))

        # The user is correctly rendered out
        self.assertEquals(u._to_net(), [{'user': 'root', 'password': None,
                                         'roles': ['root']}])

        # An inexistent user raises the appropriate exception
        u = auth.EtcdUser(self.client, 'user.does.not.exist')
        with raises(etcd.EtcdKeyNotFound):
            yield from u.read()

        # Reading with an unauthenticated client raises an exception
        u = auth.EtcdUser(self.unauth_client, 'root')
        with raises(etcd.EtcdInsufficientPermissions):
            yield from u.read()

        # Generic errors are caught
        c = etcd.Client(port=9999)
        u = auth.EtcdUser(c, 'root')
        with raises(etcd.EtcdException):
            yield from u.read()

    @helpers.run_async
    def test_write_and_delete(loop,self):
        # Create an user
        u = auth.EtcdUser(self.client, 'test_user')
        u.roles.add('guest')
        u.roles.add('root')
        # directly from my suitcase
        u.password = '123456'
        try:
            yield from u.write()
        except:
            self.fail("creating a user doesn't work")
        # Password gets wiped
        self.assertEquals(u.password, None)
        yield from u.read()
        # Verify we can log in as this user and access the auth (it has the
        # root role)
        cl = etcd.Client(port=6281, username='test_user',
                         password='123456')
        ul = auth.EtcdUser(cl, 'root')
        try:
            yield from ul.read()
        except etcd.EtcdInsufficientPermissions:
            self.fail("Reading auth with the new user is not possible")

        self.assertEquals(u.name, "test_user")
        self.assertEquals(u.roles, set(['guest', 'root']))

        # Unauthorized access is properly handled
        ua = auth.EtcdUser(self.unauth_client, 'test_user')
        with raises(etcd.EtcdInsufficientPermissions):
            yield from ua.write()

        # now let's test deletion
        du = auth.EtcdUser(self.client, 'user.does.not.exist')
        with raises(etcd.EtcdKeyNotFound):
            yield from du.delete()

        # Delete test_user
        yield from u.delete()
        with raises(etcd.EtcdKeyNotFound):
            yield from u.read()
        # Permissions are properly handled
        with raises(etcd.EtcdInsufficientPermissions):
            yield from ua.delete()


class EtcdRoleTest(TestEtcdAuthBase):
    @helpers.run_async
    def test_names(loop,self):
        r = auth.EtcdRole(self.client, 'guest')
        x = yield from r.get_names()
        print(x)
        self.assertListEqual((yield from r.get_names()), [
            {
                'role': 'guest',
                'permissions': {
                    'kv': {'read': ['/*'], 'write': ['/*']}
                }
            },
            {
                'role': 'root',
                'permissions': {
                    'kv': {'read': ['/*'], 'write': ['/*']}
                }
            }
        ])

    @helpers.run_async
    def test_read(loop,self):
        r = auth.EtcdRole(self.client, 'guest')
        try:
            yield from r.read()
        except:
            self.fail('Reading an existing role failed')

        self.assertEquals(r.acls, {'/*': 'RW'})
        # We can actually skip most other read tests as they are common
        # with EtcdUser

    @helpers.run_async
    def test_write_and_delete(loop,self):
        r = auth.EtcdRole(self.client, 'test_role')
        r.acls = {'/*': 'R', '/test/*': 'RW'}
        try:
            yield from r.write()
        except:
            self.fail("Writing a simple groups should not fail")

        r1 = auth.EtcdRole(self.client, 'test_role')
        yield from r1.read()
        self.assertEquals(r1.acls, r.acls)
        r.revoke('/test/*', 'W')
        yield from r.write()
        yield from r1.read()
        self.assertEquals(r1.acls, {'/*': 'R', '/test/*': 'R'})
        r.grant('/pub/*', 'RW')
        yield from r.write()
        yield from r1.read()
        self.assertEquals(r1.acls['/pub/*'], 'RW')
        # All other exceptions are tested by the user tests
        r1.name = None
        with raises(etcd.EtcdException):
            yield from r1.write()
        # ditto for delete
        try:
            yield from r.delete()
        except:
            self.fail("A normal delete should not fail")
        with raises(etcd.EtcdKeyNotFound):
            yield from r.read()

