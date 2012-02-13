# vim: tabstop=4 shiftwidth=4 softtabstop=4

import sqlalchemy

from keystone.identity.backends import sql as identity_sql


def export_db(db):
    table_query = db.execute("show tables")

    migration_data = {}
    for table_name in table_query.fetchall():
        table_name = table_name[0]
        query = db.execute("describe %s" % table_name)

        column_names = []
        column_attributes = {}
        for column in query.fetchall():
            column_name = column[0]
            column_attributes[column_name] = column
            column_name = table_name + "." + column_name
            column_names.append(column_name)

        table_dump = {}
        table_dump['name'] = table_name
        table_dump['column_attributes'] =  column_attributes

        query = db.execute("select %s from %s"
                           % (",".join(column_names), table_name))
        table_data = []
        for row in query.fetchall():
            entry = {}
            i = 0
            for c in column_names:
                entry[c.split('.')[1]] = row[i]
                i = i + 1
            table_data.append(entry)

        table_dump['data'] = table_data
        migration_data[table_name] = table_dump
        return migration_data


class LegacyMigration(object):
    def __init__(self, db_string):
        self.db = sqlalchemy.create_engine(db_string)
        self.identity_driver = identity_sql.Identity()
        self._data = {}
        self._user_map = {}
        self._tenant_map = {}
        self._role_map = {}

    def migrate_all(self):
        self._export_legacy_db()
        self._migrate_tenants()
        self._migrate_users()
        self._migrate_roles()
        self._migrate_user_roles()
        self._migrate_tokens()

    def dump_catalog(self, path):
        """Generate the contents of a catalog templates file."""
        pass

    def _export_legacy_db(self):
        self._data = export_db(self.db)

    def _migrate_tenants(self):
        for x in self._data['tenants']:
            # map
            new_dict = {'description': x.get('desc', ''),
                        'id': x.get('uid', x.get('id')),
                        'enabled': x.get('enabled', True)}
            new_dict['name'] = x.get('name', new_dict.get('id'))
            # track internal ids
            self._tenant_map[new_dict['id']] = x.get('id')
            # create
            self.identity_driver.create_tenant(new_dict['id'], new_dict)

    def _migrate_users(self):
        for x in self._data['users']:
            # map
            new_dict = {'email': x.get('email', ''),
                        'password': x.get('password', None),
                        'id': x.get('uid', x.get('id')),
                        'enabled': x.get('enabled', True)}
            if x.get('tenant_id'):
                new_dict['tenant_id'] = self._tenant_map.get(x['tenant_id'])
            new_dict['name'] = x.get('name', new_dict.get('id'))
            # track internal ids
            self._user_map[new_dict['id']] = x.get('id')
            # create
            self.identity_driver.create_user(new_dict['id'], new_dict)
            if new_dict.get('tenant_id'):
                self.identity_driver.add_user_to_tenant(new_dict['tenant_id'],
                                                        new_dict['id'])

    def _migrate_roles(self):
        for x in self._data['roles']:
            # map
            new_dict = {'id': x['id'],
                        'name': x.get('name', x['id'])}
            # track internal ids
            self._role_map[new_dict['id']] = x.get('id')
            # create
            self.identity_driver.create_role(new_dict['id'], new_dict)

    def _migrate_user_roles(self):
        for x in self._data['user_roles']:
            # map
            if (not x.get('user_id')
                or not x.get('tenant_id')
                or not x.get('role_id')):
                continue
            user_id = self._user_map[x['user_id']]
            tenant_id = self._tenant_map[x['tenant_id']]
            role_id = self._role_map[x['role_id']]

            try:
                self.identity_driver.add_user_to_tenant(tenant_id, user_id)
            except Exception:
                pass

            self.identity_driver.add_role_to_user_and_tenant(
                    user_id, tenant_id, role_id)

    def _migrate_tokens(self):
        pass
