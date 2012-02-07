import ldap.filter
from keystone.common import utils
import keystone.common.ldap  as common_ldap
from keystone.identity import models



def _ensure_hashed_password(user_ref):
    pw = user_ref.get('password', None)
    if pw is not None:
        pw = utils.ldap_hash_password(pw)
        user_ref['password'] = pw
    return user_ref

class UserAPI(common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Users'
    DEFAULT_STRUCTURAL_CLASSES = ['person']
    DEFAULT_ID_ATTRIBUTE = 'cn'
    DEFAULT_OBJECTCLASS='inetOrgPerson'
    options_name = 'user'
    attribute_mapping = {
        'password': 'userPassword',
        #'email': 'mail',
        'name': 'sn',
    }
    #The RFC based schemas don't have a way to indicate 'enabled'
    #the closest is the nsAccount lock,  which is on definied to
    # be part of any objectclass
    # in the future, we need to provide a way for the end user to
    #indicate the field to use and what it indicates
    attribute_ignore = ['tenant_id','enabled','tenants']
    model = models.User

    def get_by_name(self, name, filter=None):
        users = self.get_all('(%s=%s)' % \
                            (self.attribute_mapping['name'],
                             ldap.filter.escape_filter_chars(name),))
        try:
            return users[0]
        except IndexError:
            return None


    def create(self, values):
        self.affirm_unique( values)
        #values['id'] = str(uuid.uuid4())
        _ensure_hashed_password(values)
        values = super(UserAPI, self).create(values)
        tenant_id= values.get('tenant_id')
        if tenant_id is not None:
            self.api.tenant.add_user(values['tenant_id'], values['id'])
        return values

    def update(self, id, values):
        if (values['id'] != id):
            return None
        old_obj = self.get(id)
        if old_obj.name != values['name']:
            raise "Changing Name not permitted"
        try:
            new_tenant = values['tenant_id']
        except KeyError:
            pass
        else:
            if old_obj.tenant_id != new_tenant:
                if old_obj.tenant_id:
                    self.api.tenant.remove_user(old_obj.tenant_id, id)
                if new_tenant:
                    self.api.tenant.add_user(new_tenant, id)
        _ensure_hashed_password(values)
        super(UserAPI, self).update(id, values, old_obj)

    def delete(self, id):
        user = self.get(id)
        if user.tenant_id:
            self.api.tenant.remove_user(user.tenant_id, id)
        super(UserAPI, self).delete(id)
        for ref in self.api.role.list_global_roles_for_user(id):
            self.api.role.rolegrant_delete(ref.id)
        for ref in self.api.role.list_tenant_roles_for_user(id):
            self.api.role.rolegrant_delete(ref.id)

    def get_by_email(self, email):
        users = self.get_all('(mail=%s)' % \
                            (ldap.filter.escape_filter_chars(email),))
        try:
            return users[0]
        except IndexError:
            return None

    def user_roles_by_tenant(self, user_id, tenant_id):
        return self.api.role.list_tenant_roles_for_user(user_id, tenant_id)

    def get_by_tenant(self, user_id, tenant_id):
        user_dn = self._id_to_dn(user_id)
        user = self.get(user_id)
        tenant = self.api.tenant._ldap_get(tenant_id,
                                           '(member=%s)' % (user_dn,))
        if tenant is not None:
            return user
        else:
            if self.api.role.list_tenant_roles_for_user(user_id, tenant_id):
                return user
        return None

    def user_role_add(self, values):
        return self.api.role.add_user(values.role_id, values.user_id,
                                      values.tenant_id)

    def users_get_page(self, marker, limit):
        return self.get_page(marker, limit)

    def users_get_page_markers(self, marker, limit):
        return self.get_page_markers(marker, limit)

    def users_get_by_tenant_get_page(self, tenant_id, role_id, marker, limit):
        return self._get_page(marker, limit,
                self.api.tenant.get_users(tenant_id, role_id))

    def users_get_by_tenant_get_page_markers(self, tenant_id,
        role_id, marker, limit):
        return self._get_page_markers(marker, limit,
                self.api.tenant.get_users(tenant_id, role_id))

    def check_password(self, user_id, password):
        user = self.get(user_id)
        return utils.check_password(password, user.password)

#    add_redirects(locals(), SQLUserAPI, ['get_by_group', 'tenant_group',
#        'tenant_group_delete', 'user_groups_get_all',
#        'users_tenant_group_get_page', 'users_tenant_group_get_page_markers'])
