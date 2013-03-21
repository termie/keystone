# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
import errno
import os
import socket
import subprocess
import sys
import time

import eventlet
import mox
import nose.exc
from paste import deploy
import stubout
import unittest2 as unittest

from keystone import catalog
from keystone.common import kvs
from keystone.common import logging
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token


do_monkeypatch = not os.getenv('STANDARD_THREADS')
eventlet.patcher.monkey_patch(all=False, socket=True, time=True,
                              thread=do_monkeypatch)

LOG = logging.getLogger(__name__)
ROOTDIR = os.path.dirname(os.path.abspath(os.curdir))
VENDOR = os.path.join(ROOTDIR, 'vendor')
TESTSDIR = os.path.join(ROOTDIR, 'tests')
ETCDIR = os.path.join(ROOTDIR, 'etc')
CONF = config.CONF
DRIVERS = {}


cd = os.chdir


logging.getLogger('routes.middleware').level = logging.WARN


def rootdir(*p):
    return os.path.join(ROOTDIR, *p)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def testsdir(*p):
    return os.path.join(TESTSDIR, *p)


def initialize_drivers():
    DRIVERS['catalog_api'] = catalog.Manager()
    DRIVERS['identity_api'] = identity.Manager()
    DRIVERS['policy_api'] = policy.Manager()
    DRIVERS['token_api'] = token.Manager()
    return DRIVERS


def checkout_vendor(repo, rev):
    # TODO(termie): this function is a good target for some optimizations :PERF
    name = repo.split('/')[-1]
    if name.endswith('.git'):
        name = name[:-4]

    working_dir = os.getcwd()
    revdir = os.path.join(VENDOR, '%s-%s' % (name, rev.replace('/', '_')))
    modcheck = os.path.join(VENDOR, '.%s-%s' % (name, rev.replace('/', '_')))
    try:
        if os.path.exists(modcheck):
            mtime = os.stat(modcheck).st_mtime
            if int(time.time()) - mtime < 10000:
                return revdir

        if not os.path.exists(revdir):
            utils.git('clone', repo, revdir)

        cd(revdir)
        utils.git('checkout', '-q', 'master')
        utils.git('pull', '-q')
        utils.git('checkout', '-q', rev)

        # write out a modified time
        with open(modcheck, 'w') as fd:
            fd.write('1')
    except subprocess.CalledProcessError:
        LOG.warning(_('Failed to checkout %s'), repo)
    cd(working_dir)
    return revdir


class TestClient(object):
    def __init__(self, app=None, token=None):
        self.app = app
        self.token = token

    def request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {}

        if self.token:
            headers.setdefault('X-Auth-Token', self.token)

        req = wsgi.Request.blank(path)
        req.method = method
        for k, v in headers.iteritems():
            req.headers[k] = v
        if body:
            req.body = body
        return req.get_response(self.app)

    def get(self, path, headers=None):
        return self.request('GET', path=path, headers=headers)

    def post(self, path, headers=None, body=None):
        return self.request('POST', path=path, headers=headers, body=body)

    def put(self, path, headers=None, body=None):
        return self.request('PUT', path=path, headers=headers, body=body)


class NoModule(object):
    """A mixin class to provide support for unloading/disabling modules."""

    def __init__(self, *args, **kw):
        super(NoModule, self).__init__(*args, **kw)
        self._finders = []
        self._cleared_modules = {}

    def tearDown(self):
        super(NoModule, self).tearDown()
        for finder in self._finders:
            sys.meta_path.remove(finder)
        sys.modules.update(self._cleared_modules)

    def clear_module(self, module):
        cleared_modules = {}
        for fullname in sys.modules.keys():
            if fullname == module or fullname.startswith(module + '.'):
                cleared_modules[fullname] = sys.modules.pop(fullname)
        return cleared_modules

    def disable_module(self, module):
        """Ensure ImportError for the specified module."""

        # Clear 'module' references in sys.modules
        self._cleared_modules.update(self.clear_module(module))

        # Disallow further imports of 'module'
        class NoModule(object):
            def find_module(self, fullname, path):
                if fullname == module or fullname.startswith(module + '.'):
                    raise ImportError

        finder = NoModule()
        self._finders.append(finder)
        sys.meta_path.insert(0, finder)


class TestCase(NoModule, unittest.TestCase):
    def __init__(self, *args, **kw):
        super(TestCase, self).__init__(*args, **kw)
        self._paths = []
        self._memo = {}
        self._overrides = []
        self._group_overrides = {}

        # show complete diffs on failure
        self.maxDiff = None

    def setUp(self):
        super(TestCase, self).setUp()
        self.config([etcdir('keystone.conf.sample'),
                     testsdir('test_overrides.conf')])
        self.mox = mox.Mox()
        self.opt(policy_file=etcdir('policy.json'))
        self.stubs = stubout.StubOutForTesting()
        self.stubs.Set(exception, '_FATAL_EXCEPTION_FORMAT_ERRORS', True)

    def config(self, config_files):
        CONF(args=[], project='keystone', default_config_files=config_files)

    def tearDown(self):
        try:
            self.mox.UnsetStubs()
            self.stubs.UnsetAll()
            self.stubs.SmartUnsetAll()
            self.mox.VerifyAll()
            super(TestCase, self).tearDown()
        finally:
            for path in self._paths:
                if path in sys.path:
                    sys.path.remove(path)
            kvs.INMEMDB.clear()
            CONF.reset()

    def opt_in_group(self, group, **kw):
        for k, v in kw.iteritems():
            CONF.set_override(k, v, group)

    def opt(self, **kw):
        for k, v in kw.iteritems():
            CONF.set_override(k, v)

    def load_backends(self):
        """Create shortcut references to each driver for data manipulation."""
        for name, manager in initialize_drivers().iteritems():
            setattr(self, name, manager.driver)

    def load_fixtures(self, fixtures):
        """Hacky basic and naive fixture loading based on a python module.

        Expects that the various APIs into the various services are already
        defined on `self`.

        """
        # TODO(termie): doing something from json, probably based on Django's
        #               loaddata will be much preferred.
        if hasattr(self, 'identity_api'):
            for domain in fixtures.DOMAINS:
                try:
                    rv = self.identity_api.create_domain(domain['id'], domain)
                except (exception.Conflict, exception.NotImplemented):
                    pass
                setattr(self, 'domain_%s' % domain['id'], domain)

            for tenant in fixtures.TENANTS:
                try:
                    rv = self.identity_api.create_project(tenant['id'], tenant)
                except exception.Conflict:
                    rv = self.identity_api.get_project(tenant['id'])
                    pass
                setattr(self, 'tenant_%s' % tenant['id'], rv)

            for role in fixtures.ROLES:
                try:
                    rv = self.identity_api.create_role(role['id'], role)
                except exception.Conflict:
                    rv = self.identity_api.get_role(role['id'])
                    pass
                setattr(self, 'role_%s' % role['id'], rv)

            for user in fixtures.USERS:
                user_copy = user.copy()
                tenants = user_copy.pop('tenants')
                try:
                    rv = self.identity_api.create_user(user['id'],
                                                       user_copy.copy())
                except exception.Conflict:
                    pass
                for tenant_id in tenants:
                    try:
                        self.identity_api.add_user_to_project(tenant_id,
                                                              user['id'])
                    except exception.Conflict:
                        pass
                setattr(self, 'user_%s' % user['id'], user_copy)

            for metadata in fixtures.METADATA:
                metadata_ref = metadata.copy()
                # TODO(termie): these will probably end up in the model anyway,
                #               so this may be futile
                del metadata_ref['user_id']
                del metadata_ref['tenant_id']
                rv = self.identity_api.create_metadata(metadata['user_id'],
                                                       metadata['tenant_id'],
                                                       metadata_ref)
                setattr(self,
                        'metadata_%s%s' % (metadata['user_id'],
                                           metadata['tenant_id']), rv)

    def _paste_config(self, config):
        if not config.startswith('config:'):
            test_path = os.path.join(TESTSDIR, config)
            etc_path = os.path.join(ROOTDIR, 'etc', config)
            for path in [test_path, etc_path]:
                if os.path.exists('%s.conf.sample' % path):
                    return 'config:%s.conf.sample' % path
        return config

    def loadapp(self, config, name='main'):
        return deploy.loadapp(self._paste_config(config), name=name)

    def appconfig(self, config):
        return deploy.appconfig(self._paste_config(config))

    def serveapp(self, config, name=None, cert=None, key=None, ca=None,
                 cert_required=None, host="127.0.0.1", port=0):
        app = self.loadapp(config, name=name)
        server = wsgi.Server(app, host, port)
        if cert is not None and ca is not None and key is not None:
            server.set_ssl(certfile=cert, keyfile=key, ca_certs=ca,
                           cert_required=cert_required)
        server.start(key='socket')

        # Service catalog tests need to know the port we ran on.
        port = server.socket_info['socket'][1]
        self.opt(public_port=port, admin_port=port)
        return server

    def client(self, app, *args, **kw):
        return TestClient(app, *args, **kw)

    def add_path(self, path):
        sys.path.insert(0, path)
        self._paths.append(path)

    def assertCloseEnoughForGovernmentWork(self, a, b, delta=3):
        """Asserts that two datetimes are nearly equal within a small delta.

        :param delta: Maximum allowable time delta, defined in seconds.
        """
        self.assertAlmostEqual(a, b, delta=datetime.timedelta(seconds=delta))

    def assertDictContainsSubset(self, dict1, dict2):
        if len(dict1) < len(dict2):
            (subset, fullset) = dict1, dict2
        else:
            (subset, fullset) = dict2, dict1
        for x in subset:
            self.assertIn(x, fullset)
            self.assertEquals(subset.get(x), fullset.get(x))

    @staticmethod
    def skip_if_no_ipv6():
        try:
            s = socket.socket(socket.AF_INET6)
        except socket.error as e:
            if e.errno == errno.EAFNOSUPPORT:
                raise nose.exc.SkipTest("IPv6 is not enabled in the system")
            else:
                raise
        else:
            s.close()
