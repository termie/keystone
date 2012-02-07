from keystone import test
from keystone.identity.backends import ldap as identity_ldap
from keystone import config


import test_backend
import default_fixtures

CONF = config.CONF

def clear_database():
	from keystone.common.ldap.fakeldap import FakeShelve
	db = FakeShelve().get_instance()
	db.clear()

class LDAPIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
	super(LDAPIdentity, self).setUp()
	CONF(config_files=[test.etcdir('keystone.conf'),
		       test.testsdir('test_overrides.conf'),
		       test.testsdir('backend_ldap.conf')])
	clear_database()
	self.identity_api = identity_ldap.Identity()
	self.load_fixtures(default_fixtures)
	self.user_foo = {'id': 'foo', 'name': 'FOO',
			 'password': 'foo2', 'tenants': ['bar',]}

    def tearDown(self):
	test.TestCase.tearDown(self)

    #we don't plan on implementing Metadata in LDAP, so hide the failures
