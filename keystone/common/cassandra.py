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

from pycassa import columnfamily
from pycassa import index
from pycassa import pool
from pycassa import system_manager

from keystone.common import logging
from keystone import config


CONF = config.CONF
config.register_str('keyspace', group='cassandra', default='Keystone')
config.register_str('connection', group='cassandra', default='localhost:9160')
LOG = logging.getLogger(__name__)


def setup_keyspace(sysm):
    keyspace = CONF.cassandra.keyspace
    # TODO(termie): make this configurable
    sysm.create_keyspace(keyspace,
                         strategy_options={'replication_factor': '1'})


def setup_token_columnfamily(sysm):
    keyspace = CONF.cassandra.keyspace
    sysm.create_column_family(keyspace, 'Token')
    sysm.create_index(keyspace=keyspace,
                      column_family='Token',
                      column='valid',
                      value_type=system_manager.BOOLEAN_TYPE,
                      index_name='token_valid')
    sysm.create_index(keyspace=keyspace,
                      column_family='Token',
                      column='user_id',
                      value_type=system_manager.UTF8_TYPE,
                      index_name='token_user_id')
    sysm.create_index(keyspace=keyspace,
                      column_family='Token',
                      column='tenant_id',
                      value_type=system_manager.UTF8_TYPE,
                      index_name='token_tenant_id')


def setup_test_database():
    sysm = system_manager.SystemManager(CONF.cassandra.connection)
    setup_keyspace(sysm)
    setup_token_columnfamily(sysm)


def teardown_test_database():
    sysm = system_manager.SystemManager(CONF.cassandra.connection)
    sysm.drop_keyspace(CONF.cassandra.keyspace)


class Base(object):
    """Helper methods for Cassandra backends."""

    _pool = None
    _columnfamily = None

    def get_session(self):
        """Get this class's ColumnFamily or init a new one."""
        classname = self.__class__.__name__
        p = self.get_pool()
        self._columnfamily = (self._columnfamily
                              or columnfamily.ColumnFamily(p, classname))
        return self._columnfamily

    def get_pool(self):
        """Get our Cassandra connection pool or init a new one."""
        def _new_pool():
            return pool.ConnectionPool(keyspace=CONF.cassandra.keyspace,
                                       server_list=[CONF.cassandra.connection])
        self._pool = self._pool or _new_pool()
        return self._pool

    def index_clause(self, expr_list, start_key=None, count=None):
        """Shortcut for doing index searches.

        expr_list looks like:
          ((column_name, column_value, *more),
           (column_name2, column_value2, *more)
           )
        """
        clause_parts = []
        for sub_args in expr_list:
            clause_parts.append(index.create_index_expression(*sub_args))

        # This looks a little weird, but basically the create_index_clause
        # call below won't accept None as an argument even though the args
        # are optional
        params = {'expr_list': clause_parts}
        if start_key is not None:
            params['start_key'] = start_key
        if count is not None:
            params['count'] = count
        return index.create_index_clause(**params)
