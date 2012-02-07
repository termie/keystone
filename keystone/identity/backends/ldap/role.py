
import ldap
import uuid

import keystone.common.ldap as common_ldap
import  user
import  tenant
from keystone.identity import models

class UserRoleAssociation():
    """ Role Grant model """

    hints = {
        'contract_attributes': ['id', 'role_id', 'user_id', 'tenant_id'],
        'types': [('user_id', basestring), ('tenant_id', basestring)],
        'maps': {'userId': 'user_id', 'roleId': 'role_id',
                'tenantId': 'tenant_id'}
    }

    def __init__(self, user_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        # pylint: disable=E0203
        self.user_id=user_id
        self.role_id=role_id
        self.tenant_id=tenant_id
        if isinstance(self.user_id, int):
            # pylint: disable=E0203
            self.user_id = str(self.user_id)
        if isinstance(self.tenant_id, int):
            self.tenant_id = str(self.tenant_id)


# pylint: disable=W0212, W0223
class RoleAPI(common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Roles'
    DEFAULT_STRUCTURAL_CLASSES = []
    options_name = 'role'
    DEFAULT_OBJECTCLASS = 'organizationalRole'
    DEFAULT_MEMBER_ATTRIBUTE = 'roleOccupant'
    attribute_mapping = {'name': 'cn'}#, 'serviceId': 'service_id'}
    model = models.Tenant


    def __init__(self,conf):
        super(RoleAPI,self).__init__(conf)
        self.user = user.UserAPI(conf)
        self.tenant = tenant.TenantAPI(conf)
        self.member_attribute = getattr(conf.ldap,'role_member_attribute') \
           or self.DEFAULT_MEMBER_ATTRIBUTE

    @staticmethod
    def _create_ref(role_id, tenant_id, user_id):
        role_id = '' if role_id is None else str(role_id)
        tenant_id = '' if tenant_id is None else str(tenant_id)
        user_id = '' if user_id is None else str(user_id)
        return '%d-%d-%s%s%s' % (len(role_id), len(tenant_id),
                                 role_id, tenant_id, user_id)

    @staticmethod
    def _explode_ref(rolegrant):
        a = rolegrant.split('-', 2)
        len_role = int(a[0])
        len_tenant = int(a[1])
        role_id = a[2][:len_role]
        role_id = None if len(role_id) == 0 else str(role_id)
        tenant_id = a[2][len_role:len_tenant + len_role]
        tenant_id = None if len(tenant_id) == 0 else str(tenant_id)
        user_id = a[2][len_tenant + len_role:]
        user_id = None if len(user_id) == 0 else str(user_id)
        return role_id, tenant_id, user_id

    def _subrole_id_to_dn(self, role_id, tenant_id):
        if tenant_id is None:
            return self._id_to_dn(role_id)
        else:
            return "cn=%s,%s" % (ldap.dn.escape_dn_chars(role_id),
                                 self.tenant._id_to_dn(tenant_id))

    def get(self, id, filter=None):
        model = super(RoleAPI, self).get(id, filter)
        return model

    def create(self, values):
        #values['id'] = values['name']
        #delattr(values, 'name')

        return super(RoleAPI, self).create(values)

    # pylint: disable=W0221
    def get_by_name(self, name, filter=None):
        return self.get(name, filter)

    def add_user(self, role_id, user_id, tenant_id=None):
        user = self.user.get(user_id)
        if user is None:
            raise Exception("User %s not found" % (user_id,))
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.get_connection()
        user_dn = self.user._id_to_dn(user_id)
        try:
            conn.modify_s(role_dn, [(ldap.MOD_ADD,
                                     self.member_attribute, user_dn)])
        except ldap.TYPE_OR_VALUE_EXISTS:
            raise Exception(
                "User %s already has role %s in tenant %s" % (user_id,
                    role_id, tenant_id))
        except ldap.NO_SUCH_OBJECT:
            if tenant_id is None or self.get(role_id) is None:
                raise Exception("Role %s not found" % (role_id,))
            attrs = [
                ('objectClass', [self.object_class]),
                (self.member_attribute, [user_dn]),
            ]
            if self.use_dumb_member:
                attrs[1][1].append(self.DUMB_MEMBER_DN)
            try:
                conn.add_s(role_dn, attrs)
            except Exception as inst:
                    raise inst
        return UserRoleAssociation(
            id=self._create_ref(role_id, tenant_id, user_id),
            role_id=role_id, user_id=user_id, tenant_id=tenant_id)

    def get_by_service(self, service_id):
        roles = self.get_all('(service_id=%s)' % \
                    (ldap.filter.escape_filter_chars(service_id),))
        try:
            res = []
            for role in roles:
                res.append(role)
            return res
        except IndexError:
            return None

    def get_role_assignments(self, tenant_id):
        conn = self.get_connection()
        query = '(objectClass=' +self.object_class+')'
        tenant_dn = self.tenant._id_to_dn(tenant_id)
        try:
            roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []
        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs[self.member_attribute]
            except KeyError:
                continue
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                user_id = self.user._dn_to_id(user_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def list_global_roles_for_user(self, user_id):
        user_dn = self.user._id_to_dn(user_id)
        roles = self.get_all('(%s=%s)' % (self.member_attribute,user_dn,))
        return [UserRoleAssociation(
                    id=self._create_ref(role.id, None, user_id),
                    role_id=role.id,
                    user_id=user_id) for role in roles]

    def list_tenant_roles_for_user(self, user_id, tenant_id=None):
        conn = self.get_connection()
        user_dn = self.user._id_to_dn(user_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,user_dn,)
        if tenant_id is not None:
            tenant_dn = self.tenant._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return []
            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                       id=self._create_ref(role_id, tenant_id, user_id),
                       user_id=user_id,
                       role_id=role_id,
                       tenant_id=tenant_id))
            return res
        else:
            try:
                roles = conn.search_s(self.tenant.tree_dn,
                                        ldap.SCOPE_SUBTREE, query)
            except ldap.NO_SUCH_OBJECT:
                return []
            res = []
            for role_dn, _ in roles:
                role_id = self._dn_to_id(role_dn)
                tenant_id = ldap.dn.str2dn(role_dn)[1][0][1]
                res.append(UserRoleAssociation(
                       id=self._create_ref(role_id, tenant_id, user_id),
                       user_id=user_id,
                       role_id=role_id,
                       tenant_id=tenant_id))
            return res

    def rolegrant_get(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,user_dn,)
        conn = self.get_connection()
        try:
            res = conn.search_s(role_dn, ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None
        if len(res) == 0:
            return None
        return UserRoleAssociation(id=id, role_id=role_id,
                                tenant_id=tenant_id, user_id=user_id)

    def rolegrant_delete(self, id):
        role_id, tenant_id, user_id = self._explode_ref(id)
        user_dn = self.user._id_to_dn(user_id)
        role_dn = self._subrole_id_to_dn(role_id, tenant_id)
        conn = self.get_connection()
        try:
            conn.modify_s(role_dn, [(ldap.MOD_DELETE, '', [user_dn])])
        except ldap.NO_SUCH_ATTRIBUTE:
            raise Exception("No such user in role")

    def rolegrant_get_page(self, marker, limit, user_id, tenant_id):
        all_roles = []
        if tenant_id is None:
            all_roles += self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.tenant.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                                    tenant.id)
        return self._get_page(marker, limit, all_roles)

    def rolegrant_get_page_markers(self, user_id, tenant_id, marker, limit):
        all_roles = []
        if tenant_id is None:
            all_roles = self.list_global_roles_for_user(user_id)
        else:
            for tenant in self.tenant.get_all():
                all_roles += self.list_tenant_roles_for_user(user_id,
                                                                    tenant.id)
        return self._get_page_markers(marker, limit, all_roles)

    def get_by_service_get_page(self, service_id, marker, limit):
        all_roles = self.get_by_service(service_id)
        return self._get_page(marker, limit, all_roles)

    def get_by_service_get_page_markers(self, service_id, marker, limit):
        all_roles = self.get_by_service(service_id)
        return self._get_page_markers(marker, limit, all_roles)

    def rolegrant_list_by_role(self, id):
        role_dn = self._id_to_dn(id)
        try:
            roles = self.get_all('(%s=%s)' % (self.member_attribute,role_dn,))
        except ldap.NO_SUCH_OBJECT:
            return []
        res = []
        for role_dn, attrs in roles:
            try:
                user_dns = attrs[self.member_attribute]
                tenant_dns = attrs['tenant']
            except KeyError:
                continue
            for user_dn in user_dns:
                if self.use_dumb_member and user_dn == self.DUMB_MEMBER_DN:
                    continue
                user_id = self.user._dn_to_id(user_dn)
                tenant_id = None
                if tenant_dns is not None:
                    for tenant_dn in tenant_dns:
                        tenant_id = self.tenant._dn_to_id(tenant_dn)
                role_id = self._dn_to_id(role_dn)
                res.append(UserRoleAssociation(
                    id=self._create_ref(role_id, tenant_id, user_id),
                    user_id=user_id,
                    role_id=role_id,
                    tenant_id=tenant_id))
        return res

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id):
        conn = self.get_connection()
        user_dn = self.user._id_to_dn(user_id)
        query = '(&(objectClass=%s)(%s=%s))' % (self.object_class,
                                                self.member_attribute,user_dn)

        if tenant_id is not None:
            tenant_dn = self.tenant._id_to_dn(tenant_id)
            try:
                roles = conn.search_s(tenant_dn, ldap.SCOPE_ONELEVEL, query)
            except ldap.NO_SUCH_OBJECT:
                return None
            if len(roles) == 0:
                return None
            for role_dn, _ in roles:
                ldap_role_id = self._dn_to_id(role_dn)
                if role_id == ldap_role_id:
                    res = UserRoleAssociation(
                           id=self._create_ref(role_id, tenant_id, user_id),
                           user_id=user_id,
                           role_id=role_id,
                           tenant_id=tenant_id)
                    return res
        else:
            try:
                roles = self.get_all('(%s=%s)' % (self.member_attribute,
                                                  user_dn,))
            except ldap.NO_SUCH_OBJECT:
                return None
            if len(roles) == 0:
                return None
            for role in roles:
                if role.id == role_id:
                    return UserRoleAssociation(
                                id=self._create_ref(role.id, None, user_id),
                                role_id=role.id,
                                user_id=user_id)
        return None
