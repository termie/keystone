# vim: tabstop=4 shiftwidth=4 softtabstop=4

import sys
import uuid

import ldap

from keystone import config
from keystone import identity
from keystone.common import ldap as common_ldap
from keystone.common import utils
from keystone.identity.backends.ldap import user,tenant,role


CONF = config.CONF


def _filter_user(user_ref):
    if user_ref:
        user_ref.pop('password', None)
    return user_ref


class Identity(identity.Driver):
    def __init__(self):
        super(Identity, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        self.user = user.UserAPI(CONF)
        self.tenant = tenant.TenantAPI(CONF)
        self.role = role.RoleAPI(CONF)

    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = keystone.common.ldap.fakeldap.FakeLdap(self.LDAP_URL)
        else:
            conn = keystone.common.ldap.LDAPWrapper(self.LDAP_URL)
        if user is None:
            user = self.LDAP_USER
        if password is None:
            password = self.LDAP_PASSWORD
        conn.simple_bind_s(user, password)
        return conn

    def get_user(self, user_id):
        user_ref = self._get_user(user_id)
        if (not user_ref):
                return None
        return _filter_user (user_ref)

    def _get_user(self, user_id):
        user_ref = self.user.get(user_id)
        if (not user_ref):
            return None
        tenants = self.tenant.get_user_tenants(user_id)
        user_ref['tenants'] = []
        for tenant in tenants:
            user_ref['tenants'].append(tenant.id)
        return user_ref

    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.
        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.
        """
        #todo get hostname from config

        user_ref = self._get_user(user_id)
        if (user_ref == None):
            raise AssertionError('Invalid user / password')

        try:
            conn = self.user.get_connection(self.user._id_to_dn(user_id),
                                            password)
            if (not conn):
                raise AssertionError('Invalid user / password')
        except  Exception as inst:
                raise AssertionError('Invalid user / password')

        if tenant_id:
            found = False
            for tenant in user_ref['tenants']:
                if tenant == tenant_id:
                    found = True
                    break

            if (not found):
                raise AssertionError('Invalid tenant')

        #user_ref['tenant_id'] = tenant_id

        tenant_ref = self.tenant.get(tenant_id)
        metadata_ref = {}
        #if tenant_ref:
        #    metadata_ref =  self.get_metadata(user_id, tenant_id)
        #else:
        #    metadata_ref = {}
        return  (_filter_user(user_ref),tenant_ref,metadata_ref)

    def create_user(self, user_id, user):
        return self.user.create(user)

    def create_tenant(self, tenant_id, tenant):

        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4())
        return self.tenant.create(tenant)

    def add_user_to_tenant(self, tenant_id, user_id):
        return self.tenant.add_user(tenant_id, user_id)

    def create_role(self, role_id, role):
        return self.role.create(role)

    def get_role(self, role_id):
        return self.role.get(role_id)

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        assignments = self.role.get_role_assignments(tenant_id)
        roles =[]
        for assignment in assignments:
            if assignment.user_id == user_id:
                roles.append(assignment.role_id)
        return roles

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        self.role.add_user(role_id, user_id, tenant_id)

    def delete_role(self, role_id):
        return self.role.delete(role_id)

    def get_tenant_by_name(self, tenant_name):
        return self.tenant.get_by_name(tenant_name)

    def get_tenant(self, tenant_id):
        return self.tenant.get(tenant_id)

    def create_metadata(self, user_id, tenant_id, metadata):
        return {}

    def get_tenants_for_user(self, user_id):
        tenant_list = []
        for tenant in self.tenant.get_user_tenants(user_id):
            tenant_list.append(tenant.id)
        return tenant_list

    def update_user(self, user_id, user):
        return self.user.update(user_id, user)

    def update_tenant(self, tenant_id, tenant):
        return self.tenant.update(tenant_id, tenant)

    def get_metadata(self, user_id, tenant_id):
        if (not self.get_tenant(tenant_id)):
            return None
        if (not self.get_user(user_id)):
            return None

        metadata_ref = self.get_roles_for_user_and_tenant( user_id, tenant_id)
        return metadata_ref
