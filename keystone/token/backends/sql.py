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
import datetime


from keystone.common import sql
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token


class TokenModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'token'
    attributes = ['id', 'expires', 'user_id']
    id = sql.Column(sql.String(64), primary_key=True)
    expires = sql.Column(sql.DateTime(), default=None)
    extra = sql.Column(sql.JsonBlob())
    valid = sql.Column(sql.Boolean(), default=True)
    user_id = sql.Column(sql.String(64))


class Token(sql.Base, token.Driver):
    # Public interface
    def get_token(self, token_id):
        if token_id is None:
            raise exception.TokenNotFound(token_id=token_id)
        session = self.get_session()
        query = session.query(TokenModel)
        query = query.filter_by(id=token.unique_id(token_id), valid=True)
        token_ref = query.first()
        now = datetime.datetime.utcnow()
        if not token_ref:
            raise exception.TokenNotFound(token_id=token_id)
        if not token_ref.expires:
            raise exception.TokenNotFound(token_id=token_id)
        if now >= token_ref.expires:
            raise exception.TokenNotFound(token_id=token_id)
        return token_ref.to_dict()

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if not data_copy.get('expires'):
            data_copy['expires'] = token.default_expire_time()
        if not data_copy.get('user_id'):
            data_copy['user_id'] = data_copy['user']['id']

        token_ref = TokenModel.from_dict(data_copy)
        token_ref.id = token.unique_id(token_id)
        token_ref.valid = True
        session = self.get_session()
        with session.begin():
            session.add(token_ref)
            session.flush()
        return token_ref.to_dict()

    def delete_token(self, token_id):
        session = self.get_session()
        key = token.unique_id(token_id)
        with session.begin():
            token_ref = session.query(TokenModel).filter_by(id=key,
                                                            valid=True).first()
            if not token_ref:
                raise exception.TokenNotFound(token_id=token_id)
            token_ref.valid = False
            session.flush()

    def _list_tokens_for_user(self, user_id, tenant_id=None):
        def tenant_matches(tenant_id, token_ref_dict):
            return ((tenant_id is None) or
                    (token_ref_dict.get('tenant') and
                     token_ref_dict['tenant'].get('id') == tenant_id))

        session = self.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        query = query.filter(TokenModel.user_id == user_id)

        token_references = query.filter_by(valid=True)
        for token_ref in token_references:
            token_ref_dict = token_ref.to_dict()
            if tenant_matches(tenant_id, token_ref_dict):
                tokens.append(token_ref['id'])
        return tokens

    def list_tokens(self, user_id, tenant_id=None):
        return self._list_tokens_for_user(user_id, tenant_id)

    def list_revoked_tokens(self):
        session = self.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        token_references = query.filter_by(valid=False)
        for token_ref in token_references:
            record = {
                'id': token_ref['id'],
                'expires': token_ref['expires'],
            }
            tokens.append(record)
        return tokens
