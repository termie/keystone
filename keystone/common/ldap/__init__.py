import ast
import eventlet.tpool
import fakeldap
import itertools
import ldap
import logging
import thread

LOG = logging.getLogger('keystone.common.ldap')


LDAP_VALUES = {
    'TRUE': True,
    'FALSE': False,
}

def py2ldap(val):
    if isinstance(val, str):
        return val
    elif isinstance(val, bool):
        return 'TRUE' if val else 'FALSE'
    else:
        return str(val)


def ldap2py(val):
    try:
        return LDAP_VALUES[val]
    except KeyError:
        pass
    try:
        return int(val)
    except ValueError:
        pass
    return val


def safe_iter(attrs):
    if attrs is None:
        return
    elif isinstance(attrs, list):
        for e in attrs:
            yield e
    else:
        yield attrs


class BaseLdap(object):
    DEFAULT_SUFFIX="dc=example,dc=com"
    DEFAULT_OU = None
    DEFAULT_STRUCTURAL_CLASSES = None
    DEFAULT_ID_ATTR = 'cn'
    DUMB_MEMBER_DN = 'cn=dumb,dc=nonexistent'
    options_name = None

    model = None
    attribute_mapping = {}
    attribute_ignore = []
    model = None
    tree_dn = None

    def __init__(self,  conf):
        #self.api = API(conf)
        self.LDAP_URL = conf.ldap.url
        self.LDAP_USER = conf.ldap.user
        self.LDAP_PASSWORD = conf.ldap.password

        if self.options_name is not None:
            self.suffix = conf.ldap.suffix
            if (self.suffix == None):
                self.suffix = self.DEFAULT_SUFFIX
            dn = '%s_tree_dn' % self.options_name
            self.tree_dn = getattr(conf.ldap, dn)  \
                 or self.suffix + ',' + self.DEFAULT_OU

            idatt = '%s_id_attribute' % self.options_name
            self.id_attr = getattr(conf.ldap,idatt) or self.DEFAULT_ID_ATTR

            objclass = '%s_objectclass' % self.options_name
            self.object_class = getattr(conf.ldap,objclass) \
                or self.DEFAULT_OBJECTCLASS

            lst = self.DEFAULT_STRUCTURAL_CLASSES
            self.structural_classes = ast.literal_eval(str(lst))

        self.use_dumb_member = getattr(conf.ldap,'use_dumb_member') or True


    def get_connection(self, user=None, password=None):
        if self.LDAP_URL.startswith('fake://'):
            conn = fakeldap.initialize(self.LDAP_URL)
        else:
#            conn = eventlet.tpool.Proxy(LDAPWrapper(self.LDAP_URL))
            conn = LDAPWrapper(self.LDAP_URL)
        if user is None:
            user = self.LDAP_USER
        if password is None:
            password = self.LDAP_PASSWORD
        conn.simple_bind_s(user, password)
        return conn


    def _id_to_dn(self, id):
        return '%s=%s,%s' % (self.id_attr, ldap.dn.escape_dn_chars(str(id)),
                                self.tree_dn)

    @staticmethod
    def _dn_to_id(dn):
        return ldap.dn.str2dn(dn)[0][0][1]

    # pylint: disable=E1102
    def _ldap_res_to_model(self, res):
        obj = self.model(id=self._dn_to_id(res[0]))
        #obj['name'] = obj['id']
        for k in obj:
            if k in self.attribute_ignore:
                continue
            try:
                v = res[1][self.attribute_mapping.get(k, k)]
            except KeyError:
                pass
            else:
                try:
                    obj[k] = v[0]
                except IndexError:
                    obj[k] = None
        return obj

    def affirm_unique(self, values):
        if (values['name'] != None):
            entity = self.get_by_name(values['name'])
            if ( entity != None ):
                raise Exception( "%s with id %s already exists"
                                 % (self.options_name,values['id']))

        if (values['id'] != None):
            entity = self.get(values['id'])
            if ( entity != None ):
                raise Exception( "%s with id %s already exists"
                                 % (self.options_name,values['id']))


    # pylint: disable=E1102
    def create(self, values):
        conn = self.get_connection()
        object_classes = self.structural_classes + [self.object_class]
        attrs = [('objectClass', object_classes)]
        for k, v in values.iteritems():
            if k == 'id' or k in self.attribute_ignore:
                continue
            if v is not None:
                attr_type = self.attribute_mapping.get(k, k)
                attrs.append((attr_type, [v]))
        if 'groupOfNames' in object_classes and self.use_dumb_member:
            attrs.append(('member', [self.DUMB_MEMBER_DN]))
        conn.add_s(self._id_to_dn(values['id']), attrs)
        return values

    def _ldap_get(self, id, filter=None):
        conn = self.get_connection()
        query = '(objectClass=%s)' % (self.object_class,)
        if filter is not None:
            query = '(&%s%s)' % (filter, query)
        try:
            res = conn.search_s(self._id_to_dn(id), ldap.SCOPE_BASE, query)
        except ldap.NO_SUCH_OBJECT:
            return None
        try:
            return res[0]
        except IndexError:
            return None

    def _ldap_get_all(self, filter=None):
        conn = self.get_connection()
        query = '(objectClass=%s)' % (self.object_class,)
        if filter is not None:
            query = '(&%s%s)' % (filter, query)
        try:
            return conn.search_s(self.tree_dn, ldap.SCOPE_ONELEVEL, query)
        except ldap.NO_SUCH_OBJECT:
            return []

    def get(self, id, filter=None):
        res = self._ldap_get(id, filter)
        if res is None:
            return None
        else:
            return self._ldap_res_to_model(res)

    # pylint: disable=W0141
    def get_all(self, filter=None):
        return map(self._ldap_res_to_model, self._ldap_get_all(filter))

    def get_page(self, marker, limit):
        return self._get_page(marker, limit, self.get_all())

    def get_page_markers(self, marker, limit):
        return self._get_page_markers(marker, limit, self.get_all())

    # pylint: disable=W0141
    @staticmethod
    def _get_page(marker, limit, lst, key=lambda e: e.id):
        lst.sort(key=key)
        if not marker:
            return lst[:limit]
        else:
            return filter(lambda e: key(e) > marker, lst)[:limit]

    @staticmethod
    def _get_page_markers(marker, limit, lst, key=lambda e: e.id):
        if len(lst) < limit:
            return (None, None)
        lst.sort(key=key)
        if marker is None:
            if len(lst) <= limit + 1:
                nxt = None
            else:
                nxt = key(lst[limit])
            return (None, nxt)

        for i, item in itertools.izip(itertools.count(), lst):
            k = key(item)
            if k >= marker:
                break
        # pylint: disable=W0631
        if i <= limit:
            prv = None
        else:
            prv = key(lst[i - limit])
        if i + limit >= len(lst) - 1:
            nxt = None
        else:
            nxt = key(lst[i + limit])
        return (prv, nxt)

    def update(self, id, values, old_obj=None):
        if old_obj is None:
            old_obj = self.get(id)
        modlist = []
        for k, v in values.iteritems():
            if k == 'id' or k in self.attribute_ignore:
                continue
            if v is None:
                if old_obj[k] is not None:
                    modlist.append((ldap.MOD_DELETE,
                         self.attribute_mapping.get(k, k), None))
            else:
                if old_obj[k] != v:
                    if old_obj[k] is None:
                        op = ldap.MOD_ADD
                    else:
                        op = ldap.MOD_REPLACE
                    modlist.append((op, self.attribute_mapping.get(k, k), [v]))
        conn = self.get_connection()
        conn.modify_s(self._id_to_dn(id), modlist)

    def delete(self, id):
        conn = self.get_connection()
        conn.delete_s(self._id_to_dn(id))


class LDAPWrapper(object):
    def __init__(self, url):
        LOG.debug("LDAP init: url=%s", url)
        self.conn = ldap.initialize(url)

    def simple_bind_s(self, user, password):
        LOG.debug("LDAP bind: dn=%s", user)
        return self.conn.simple_bind_s(user, password)

    def add_s(self, dn, attrs):
        ldap_attrs = [(typ, map(py2ldap, safe_iter(values)))
                      for typ, values in attrs]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_attrs = [(typ, values if typ != 'userPassword' else ['****'])
                          for typ, values in ldap_attrs]
            LOG.debug("LDAP add: dn=%s, attrs=%s", dn, sane_attrs)
        return self.conn.add_s(dn, ldap_attrs)

    def search_s(self, dn, scope, query):
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("LDAP search: dn=%s, scope=%s, query=%s", dn,
                        fakeldap.scope_names[scope], query)
        res = self.conn.search_s(dn, scope, query)
        return [(dn, dict([(typ, map(ldap2py, values))
                           for typ, values in attrs.iteritems()]))
                for dn, attrs in res]

    def modify_s(self, dn, modlist):
        ldap_modlist = [(op, typ, None if values is None else
                         map(py2ldap, safe_iter(values)))
                        for op, typ, values in modlist]
        if LOG.isEnabledFor(logging.DEBUG):
            sane_modlist = [(op, typ, values if typ != 'userPassword'
                            else ['****']) for op, typ, values in ldap_modlist]
            LOG.debug("LDAP modify: dn=%s, modlist=%s", dn, sane_modlist)
        return self.conn.modify_s(dn, ldap_modlist)

    def delete_s(self, dn):
        LOG.debug("LDAP delete: dn=%s", dn)
        return self.conn.delete_s(dn)
