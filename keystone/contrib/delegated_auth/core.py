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

"""Extensions supporting delegated auth."""


from keystone.common import controller
from keystone.common import dependency
from keystone.common import manager
from keystone.common import oauth
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import token


CONF = config.CONF


@dependency.provider('oauth_api')
class Manager(manager.Manager):
    """Default pivot point for the delegated auth credentials backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.oauth.driver)


class DelegatedAuthExtension(wsgi.ExtensionRouter):
    """API Endpoints for the Delegated Auth extension.

    The goal of this extension is to allow third-party service providers
    to acquire tokens with a limited subset of a user's roles for acting
    on behalf of that user. This is done using an oauth-similar flow and
    api.

    The API looks like:

      # Basic admin-only consumer crud
      POST /delegated_auth/consumer
      PUT /delegated_auth/consumer/$consumer_id
      GET /delegated_auth/consumer/$consumer_id
      DELETE /delegated_auth/consumer/$consumer_id

      # User access token crud
      GET /delegated_auth/user/$user_id/authorizations
      DELETE /delegated_auth/user/$user_id/authorization/$access_token

      # Public interface for third-party
      POST /delegated_auth/authenticate  # request a keystone token using an
                                         # access token

      # Public oauth interface for third-party
      GET /oauth/request_token  # get a request token for the user to authz
      GEt /oauth/access_token  # get an access token when a request token has
                               # has been authorized

      # Public oauth interface for the user
      GET /oauth/authorize  # a url the user may request to get an authz PIN
                            # to hand to the service
      POST /oauth/authorize  # authorize a specific request token

    """

    def add_routes(self, mapper):
        #da_controller
        consumer_controller = ConsumerCrudV3()
        authz_controller = AuthorizationCrudV3()
        oauth_controller = OauthFlowManiaV3()

        # request keystone token
        mapper.connect(
            '/DA/authenticate',
            controller=oauth_controller,
            action='authenticate',
            conditions=dict(method=['POST']))

        # Basic admin-only consumer crud
        mapper.connect(
            '/DA/consumer',
            controller=consumer_controller,
            action='create_consumer',
            conditions=dict(methods=['POST']))
        mapper.connect(
            '/DA/consumer/{consumer_id}',
            controller=consumer_controller,
            action='get_consumer',
            conditions=dict(methods=['GET']))
        mapper.connect(
            '/DA/consumer/{consumer_id}',
            controller=consumer_controller,
            action='update_consumer',
            conditions=dict(methods=['PUT']))
        mapper.connect(
            '/DA/consumer/{consumer_id}',
            controler=consumer_controller,
            action='delete_consumer',
            conditions=dict(methods=['DELETE']))

        # user accesss token crud
        mapper.connect(
            '/DA/user/{user_id}/authorizations',
            controller=authz_controller,
            action='list_user_authorizations',
            conditions=dict(methods=['GET']))
        mapper.connect(
            '/DA/user/{user_id}/authorization/{authz_id}',
            controler=authz_controller,
            action='delete_user_authorization',
            conditions=dict(methods=['DELETE']))

        # public oauth third-party
        mapper.connect(
            '/oauth/request_token',
            controller=oauth_controller,
            action='create_request_token',
            conditions=dict(methods=['GET']))
        mapper.connect(
            '/oauth/access_token',
            controller=oauth_controller,
            action='create_access_token',
            conditions=dict(methods=['POST']))

        # public oauth user
        mapper.connect(
            '/oauth/authorize',
            controller=oauth_controller,
            action='get_authorization_pin',
            conditions=dict(methods=['GET']))
        mapper.connect(
            '/oauth/authorize',
            controller=oauth_controller,
            action='authorize_request_token',
            conditions=dict(methods=['POST']))


#@dependency.requires('oauth_api')
class ConsumerCrudV3(controller.V3Controller):
    collection_name = 'consumers'
    member_name = 'consumer'

    @controller.protected
    def create_consumer(self, context, consumer):
        ref = self._assign_unique_id(self._normalize_dict(consumer))
        ref = self._normalize_domain_id(context, ref)
        consumer_ref = self.oauth_api.create_consumer(context, ref)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected
    def update_consumer(self, context, consumer_id, consumer):
        self._require_matching_id(consumer_id, consumer)
        ref = self._normalize_dict(consumer)
        ref = self.oauth_api.update_consumer(context, consumer_id, consumer)
        return ConsumerCrudV3.wrap_member(context, ref)

    @controller.protected
    def get_consumer(self, context, consumer_id):
        ref = self.oauth_api.get_consumer(context, consumer_id)
        return ConsumerCrudV3.wrap_member(context, ref)

    @controller.protected
    def delete_consumer(self, context, consumer_id):
        return self.oauth_api.delete_consumer(context, consumer_id)


#@dependency.requires('oauth_api')
class AuthorizationCrudV3(controller.V3Controller):
    collection_name = 'authorizations'
    member_name = 'authorization'

    @controller.protected
    def list_user_authorizations(self, context, user_id):
        refs = self.oauth_api.list_user_authorizations(context, user_id)
        return ConsumerCrudV3.wrap_collection(context, refs)

    @controller.protected
    def delete_user_authorization(self, context, user_id, authz_id):
        self._delete_tokens_for_user(context, user_id)
        return self.oauth_api.delete_user_authorization(
            context, user_id, authz_id)


class DummyOauthDriver(object):
    def get_consumer(self, context, consumer_id):
        return oauth.Consumer('foo-key', 'foo-secret')

    def create_request_token(self, context, consumer_id, roles):
        """Make a request token that the the user must authorize."""
        return {'id': 'req-key', 'secret': 'req-secret'}


#@dependency.requires('oauth_api')
class OauthFlowManiaV3(controller.V3Controller):
    collection_name = 'not_used'
    member_name = 'not_used'

    def create_request_token(self, context):
        self.oauth_api = DummyOauthDriver()
        request = context['request']
        consumer_key = request.GET.get('oauth_consumer_key')
        consumer = self.oauth_api.get_consumer(context, consumer_key)

        oauth_request = oauth.Request.from_request(
            http_method='GET',
            http_url=request.path_url,
            headers=request.headers,
            query_string=request.query_string)

        oauth_server = oauth.Server(
            {'HMAC-SHA1': oauth.SignatureMethod_HMAC_SHA1()})

        params = oauth_server.verify_request(
            oauth_request, consumer, token=None)
        roles = params['requested_roles'].split(',')

        token = self.oauth_api.create_request_token(
            context, consumer_key, roles)
        return {'request_token': token['id'],
                'request_token_secret': token['secret']}

    def create_access_token(self, context):
        # boilerplate duplicated from above
        self.oauth_api = DummyOauthDriver()
        request = context['request']
        consumer_key = request.GET.get('oauth_consumer_key')
        request_token_key = request.GET.get('oauth_request_token')
        consumer = self.oauth_api.get_consumer(context, consumer_key)
        request_token = self.oauth_api.get_request_token(
            context, request_token_key)

        oauth_request = oauth.Request.from_request(
            http_method='GET',
            http_url=request.path_url,
            headers=request.headers,
            query_string=request.query_string)

        oauth_server = oauth.Server(
            {'HMAC-SHA1': oauth.SignatureMethod_HMAC_SHA1()})

        params = oauth_server.verify_request(
            oauth_request, consumer, token=request_token)

        if request_token['consumer'] != params['consumer_key']:
            raise exception.Unauthorized()

        # do a bunch of checks
        if (not request_token.get('user_id')
            or not request_token.get('tenant_id')):
            raise exception.Unauthorized()

        access_token = self.oauth_api.create_access_token(
            context,
            user_id=request_token['user_id'],
            tenant_id=request_token['tenant_id'],
            consumer_id=request_token['consumer_id'],
            roles=request_token['roles'])
        return {'access_token': access_token['id'],
                'access_token_secret': access_token['secret']}

    def authenticate(self, context):
        """Turn a signed request with an access key into a keystone token."""
        # boilerplate duplicated from above
        self.oauth_api = DummyOauthDriver()
        request = context['request']
        consumer_key = request.POST.get('oauth_consumer_key')
        access_token_key = request.POST.get('oauth_access_token')
        consumer = self.oauth_api.get_consumer(context, consumer_key)
        access_token = self.oauth_api.get_access_token(
            context, access_token_key)

        oauth_request = oauth.Request.from_request(
            http_method='POST',
            http_url=request.path_url,
            headers=request.headers,
            query_string=request.query_string)

        oauth_server = oauth.Server(
            {'HMAC-SHA1': oauth.SignatureMethod_HMAC_SHA1()})

        params = oauth_server.verify_request(
            oauth_request, consumer, token=request_token)

        if access_token['consumer'] != params['consumer_key']:
            raise exception.Unauthorized()

        # INSERT TOKEN GENERATION CODE HERE


    def authorize(self, context, request_token_id, requested_roles):
        """An authenticated user is going to authorize a request token.

        As a security precaution, the requested roles must match those in
        the request token. Because this is in a CLI-only world at the moment,
        there is not another easy way to make sure the user knows which roles
        are being requested before authorizing.
        """
        # get the current user
        # TODO(termie): this obvs need to turn into a helper function
        user_token_ref = self.token_api.get_token(context,
                                                  token_id=context['token_id'])
        creds = user_token_ref['metadata'].copy()
        # translate roles to names
        creds['roles'] = [self.identity_api.get_role(context, role)['name']
                          for role in creds.get('roles', [])]

        creds['user_id'] = user_token_ref['user'].get('id')
        creds['tenant_id'] = user_token_ref['tenant'].get('id')

        # verify that the user has the requested roles
        roles = requested_roles.split(',')
        if set(roles) not in set(creds['roles']):
            raise exception.Unauthorized()

        # grab the request token
        req_token_ref = self.oauth_api.get_request_token(context,
                                                         request_token_id)
        req_token_roles = req_token_ref['roles']

        # make sure the roles match
        if set(req_token_roles) != set(roles):
            raise exception.Unauthorized()

        authed_token_ref = self.oauth_api.authorize_request_token(
            context, request_token_id, creds['user_id'], creds['tenant_id'])

        return {'request_token': authed_token_ref['id'],
                'oauth_verifier': authed_token_ref['verifier']}
