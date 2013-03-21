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

from keystone.common import kvs
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token


class Token(kvs.Base, token.Driver):

    # Public interface
    def get_token(self, token_id):
        token_id = token.unique_id(token_id)
        try:
            ref = self.db.get('token-%s' % token_id)
        except exception.NotFound:
            raise exception.TokenNotFound(token_id=token_id)
        now = timeutils.utcnow()
        expiry = ref['expires']
        if expiry is None:
            raise exception.TokenNotFound(token_id=token_id)
        if expiry > now:
            return copy.deepcopy(ref)
        else:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        token_id = token.unique_id(token_id)
        data_copy = copy.deepcopy(data)
        if not data_copy.get('expires'):
            data_copy['expires'] = token.default_expire_time()
        if not data_copy.get('user_id'):
            data_copy['user_id'] = data_copy['user']['id']
        self.db.set('token-%s' % token_id, data_copy)
        return copy.deepcopy(data_copy)

    def delete_token(self, token_id):
        token_id = token.unique_id(token_id)
        try:
            token_ref = self.get_token(token_id)
            self.db.delete('token-%s' % token_id)
            self.db.set('revoked-token-%s' % token_id, token_ref)
        except exception.NotFound:
            raise exception.TokenNotFound(token_id=token_id)

    def is_not_expired(self, now, ref):
        return not ref.get('expires') and ref.get('expires') < now

    def is_expired(self, now, ref):
        return ref.get('expires') and ref.get('expires') < now

    def _list_tokens_for_user(self, user_id, tenant_id=None):
        def user_matches(user_id, ref):
            return ref.get('user') and ref['user'].get('id') == user_id

        def tenant_matches(tenant_id, ref):
            return ((tenant_id is None) or
                    (ref.get('tenant') and
                     ref['tenant'].get('id') == tenant_id))

        tokens = []
        now = timeutils.utcnow()
        for token, ref in self.db.items():
            if not token.startswith('token-') or self.is_expired(now, ref):
                continue
            else:
                if (user_matches(user_id, ref) and
                        tenant_matches(tenant_id, ref)):
                        tokens.append(token.split('-', 1)[1])
        return tokens

    def list_tokens(self, user_id, tenant_id=None):
        return self._list_tokens_for_user(user_id, tenant_id)

    def list_revoked_tokens(self):
        tokens = []
        for token, token_ref in self.db.items():
            if not token.startswith('revoked-token-'):
                continue
            record = {}
            record['id'] = token_ref['id']
            record['expires'] = token_ref['expires']
            tokens.append(record)
        return tokens
