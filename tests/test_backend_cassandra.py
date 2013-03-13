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

import uuid

from keystone import catalog
from keystone.common import cassandra
from keystone import config
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import test
from keystone import token

import default_fixtures
import test_backend


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class CassandraTests(test.TestCase):
    def setUp(self):
        super(CassandraTests, self).setUp()
        self.config([test.etcdir('keystone.conf.sample'),
                     test.testsdir('test_overrides.conf'),
                     test.testsdir('backend_cassandra.conf')])

        # initialize managers and override drivers
        self.catalog_man = catalog.Manager()
        self.identity_man = identity.Manager()
        self.token_man = token.Manager()
        self.policy_man = policy.Manager()

        # create shortcut references to each driver
        self.catalog_api = self.catalog_man.driver
        self.identity_api = self.identity_man.driver
        self.token_api = self.token_man.driver
        self.policy_api = self.policy_man.driver

        # populate the engine with tables & fixtures
        cassandra.setup_test_database()
        self.load_fixtures(default_fixtures)
        #defaulted by the data load
        #self.user_foo['enabled'] = True

    def tearDown(self):
        cassandra.teardown_test_database()
        super(CassandraTests, self).tearDown()


class CassandraToken(CassandraTests, test_backend.TokenTests):
    pass
