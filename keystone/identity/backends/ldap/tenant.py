import ldap
import uuid

import keystone.common.ldap  as common_ldap
import  user

from keystone.identity import models

class TenantApi(common_ldap.BaseLdap):  # pylint: disable=W0223
    DEFAULT_OU = 'ou=Groups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTRIBUTE = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE ='member'
    options_name = 'tenant'
    attribute_mapping = {
                         #'description': 'desc', 'enabled': 'keystoneEnabled',
                         'name': 'ou'}
    model = models.Tenant

    def __init__(self,conf):
        super(TenantApi,self).__init__(conf)
        self.user = user.UserApi(conf)
        self.member_attribute = getattr(conf.ldap,'tenant_member_attribute') \
            or self.DEFAULT_MEMBER_ATTRIBUTE

    def get_by_name(self, name, filter=None):  # pylint: disable=W0221,W0613
        search_filter = '(%s=%s)' % \
                            (self.attribute_mapping['name'],
                             ldap.filter.escape_filter_chars(name),)
        tenants = self.get_all(search_filter)
        try:
            return tenants[0]
        except IndexError:
            return None

    def create(self, values):
        self.affirm_unique(values)

        data = values.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4())
        return super(TenantApi, self).create(data)

    def get_user_tenants(self, user_id):
        """Returns list of tenants a user has access to

        Always includes default tenants.
        """
        user_dn = self.user._id_to_dn(user_id)  # pylint: disable=W0212
        query = '(%s=%s)' % (self.member_attribute,user_dn,)
        memberships = self.get_all(query)
        return memberships

    def xxxget_user_tenants(self, user_id, include_roles=True):
        """Returns list of tenants a user has access to

        Always includes default tenants.
        Adds role assignments if 'include_roles' is True.
        """
        user_dn = self.user._id_to_dn(user_id)  # pylint: disable=W0212
        query = '(%s=%s)' % (self.member_attribute,user_dn,)
        memberships = self.get_all(query)
        if include_roles:
            roles = self.role.list_tenant_roles_for_user(user_id)
            for role in roles:
                exists = False
                for tenant in memberships:
                    if tenant['id'] == role.tenant_id:
                        exists = True
                        break
                if not exists:
                    memberships.append(self.get(role.tenant_id))
        return memberships


    def list_for_user_get_page(self, user, marker, limit):
        return self._get_page(marker, limit, self.get_user_tenants(user.id))

    def list_for_user_get_page_markers(self, user, marker, limit):
        return self._get_page_markers(marker, limit,
                        self.get_user_tenants(user.id))

    def is_empty(self, id):
        tenant = self._ldap_get(id)
        members = tenant[1].get(self.member_attribute, [])
        if self.use_dumb_member:
            empty = members == [self.DUMB_MEMBER_DN]
        else:
            empty = len(members) == 0
        return empty and len(self.api.role.get_role_assignments(id)) == 0

    def get_role_assignments(self, tenant_id):
        return self.api.role.get_role_assignments(tenant_id)

    def add_user(self, tenant_id, user_id):
        conn = self.get_connection()
        conn.modify_s(self._id_to_dn(tenant_id),
            [(ldap.MOD_ADD, self.member_attribute,
              self.user._id_to_dn(user_id))])  # pylint: disable=W0212

    def remove_user(self, tenant_id, user_id):
        conn = self.get_connection()
        conn.modify_s(self._id_to_dn(tenant_id),
            [(ldap.MOD_DELETE, self.member_attribute,
              self.user._id_to_dn(user_id))])  # pylint: disable=W0212

    def get_users(self, tenant_id, role_id=None):
        tenant = self._ldap_get(tenant_id)
        res = []
        if not role_id:
            # Get users who have default tenant mapping
            for user_dn in tenant[1].get(self.member_attribute, []):
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                #pylint: disable=W0212
                res.append(self.user.get(self.user._dn_to_id(user_dn)))
        rolegrants = self.api.role.get_role_assignments(tenant_id)
        # Get users who are explicitly mapped via a tenant
        for rolegrant in rolegrants:
            if role_id is None or rolegrant.role_id == role_id:
                res.append(self.user.get(rolegrant.user_id))
        return res

    def delete(self, id):
        super(TenantApi, self).delete(id)

    def update(self, id, values):
        old_obj = self.get(id)
        if old_obj.name != values['name']:
            raise "Changing Name not permitted"
        super(TenantApi, self).update(id, values,old_obj)
