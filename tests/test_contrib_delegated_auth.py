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

import webob

from keystone import test
from keystone.common import oauth
from keystone.contrib.delegated_auth import core as delegated_auth


class OauthFlowTest(test.TestCase):
    def _wsgi_request(self, *args, **kw):
        return webob.Request.blank(*args, **kw)

    def _oauth_request(self, consumer, token=None, **kw):
        return oauth.Request.from_consumer_and_token(consumer=consumer,
                                                     token=token,
                                                     **kw)

    def setUp(self):
        super(OauthFlowTest, self).setUp()
        self.controller = delegated_auth.OauthFlowManiaV3()
        self.consumer = oauth.Consumer('foo-key', 'foo-secret')
        self.base_url = 'https://localhost:5000'

    def test_request_token(self):
        oreq = self._oauth_request(
            consumer=self.consumer,
            http_url=self.base_url + '/oauth/request_token',
            parameters={'requested_roles': 'flippyfloppy'})
        oreq.sign_request(
            oauth.SignatureMethod_HMAC_SHA1(), self.consumer, None)
        wreq = self._wsgi_request(oreq.to_url())
        print wreq

        token = self.controller.create_request_token(context={'request': wreq})
