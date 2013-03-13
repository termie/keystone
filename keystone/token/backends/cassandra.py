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

import copy
import json

import pycassa

from keystone.common import cassandra
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token


"""Cassandra backend for Tokens.

Token column layout looks like:
    token_id:
        user_id: user_id
        tenant_id: tenant_id
        valid: boolean
        expires: timestamp
        extras: json blob
"""


CONF = config.CONF


def utf8_please(s):
    if isinstance(s, dict):
        return dict((utf8_please(k), utf8_please(v)) for k, v in s.iteritems())
    if type(s) is not type(u''):
        return s
    return s.encode('utf8')


def to_dict(token_ref, include_extra_dict=False):
    """Take a token as returned from Cassandra and make it a canonical dict."""
    base = {'id': token_ref['token_id']}

    # NOTE(termie): expires is apparently optional, but if it is around we need
    #               to deserialize it, else fill it in with None
    if 'expires' in token_ref:
        base['expires'] = timeutils.parse_strtime(token_ref['expires'])
    else:
        base['expires'] = None

    extra = utf8_please(json.loads(token_ref.get('extra', '{}')))
    out = extra.copy()

    # NOTE(termie): it seems consumers of this want not-unicode
    out.update(base)
    #out = dict((str(k), str(v)) for k, v in out.iteritems())
    if include_extra_dict:
        out['extra'] = extra
    return out


def from_dict(token_dict):
    """Turn something like a token dict into Cassandra columns."""
    base = {'valid': token_dict.pop('valid', True)}

    # NOTE(termie): apparently 'None' is a valid option for expires,
    #               but if no expires is specified we want to fill
    #               in the default, fml
    if 'expires' in token_dict:
        if token_dict['expires']:
            base['expires'] = timeutils.strtime(token_dict['expires'])
        del token_dict['expires']
    else:
        expires = token.default_expire_time()
        base['expires'] = timeutils.strtime(expires)

    base['extra'] = json.dumps(token_dict)

    # We expect create_token calls to pass in the user, tenant and catalog
    additional = {'user_id': token_dict.get('user', {}).get('id'),
                  'tenant_id': token_dict.get('tenant', {}).get('id')}

    # NOTE(termie): It seems there are still people using tenant-less tokens,
    #               while I think that is a bad idea, many tests will fail
    #               if we don't support that and I don't feel like boiling
    #               the sea today.
    if not additional['tenant_id']:
        del additional['tenant_id']

    base.update(additional)
    return base


class Token(cassandra.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        if token_id is None:
            raise exception.TokenNotFound(token_id=token_id)

        session = self.get_session()
        try:
            token_cols = session.get(token.unique_id(token_id))
        except pycassa.NotFoundException:
            raise exception.TokenNotFound(token_id=token_id)

        if not token_cols.get('valid', True):
            raise exception.TokenNotFound(token_id=token_id)

        token_ref = to_dict(token_cols)

        # NOTE(termie): even though we expect cassandra to expire our
        #               tokens via the TTL, the tests expect to be able
        #               to test negative expirations
        #               ... and None expirations
        if token_ref['expires'] and token_ref['expires'] < timeutils.utcnow():
            raise exception.TokenNotFound(token_id=token_id)

        return token_ref

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        ttl = None

        token_cols = from_dict(data_copy)

        # Figure out a TTL to use, taking into account weird optional expiry
        if 'expires' in data_copy and data_copy['expires']:
            expires = data_copy['expires']
            td = expires - timeutils.utcnow()
            total_secs = (td.microseconds
                          + (td.seconds
                             + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6
            if total_secs > 0:
                ttl = total_secs
        elif 'expires' not in data_copy:
            ttl = CONF.token.expiration

        token_cols['token_id'] = token.unique_id(token_id)
        session = self.get_session()
        session.insert(token.unique_id(token_id), token_cols, ttl=ttl)
        return to_dict(token_cols)

    def delete_token(self, token_id):
        key = token.unique_id(token_id)
        session = self.get_session()

        # We are actually just marking it as invalid.
        try:
            token_cols = session.get(key)
        except pycassa.NotFoundException:
            raise exception.TokenNotFound(token_id=token_id)
        if not token_cols.get('valid', True):
            raise exception.TokenNotFound(token_id=token_id)

        # NOTE(termie): ... and only mark the tokens as invalid rather than
        #               deleting them
        token_cols['valid'] = False
        session.insert(key, token_cols)

    # NOTE(termie): this returns string IDs, unlike list_revoked_tokens
    def list_tokens(self, user_id, tenant_id=None):
        session = self.get_session()

        expr_list = [('user_id', user_id),
                     ('valid', True)]
        if tenant_id is not None:
            expr_list.insert(1, ('tenant_id', tenant_id))

        clause = self.index_clause(expr_list)
        token_cols_list = session.get_indexed_slices(clause)
        return [t[1]['token_id'] for t in token_cols_list]

    # NOTE(termie): This returns dicts, unlike list_tokens
    def list_revoked_tokens(self):
        session = self.get_session()

        expr_list = [('valid', False)]

        clause = self.index_clause(expr_list)
        token_cols_list = session.get_indexed_slices(clause)
        return [to_dict(t[1]) for t in token_cols_list]
