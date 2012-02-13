# vim: tabstop=4 shiftwidth=4 softtabstop=4

import sqlalchemy


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
        self._user_map = {}
        self._tenant_map = {}
        self._role_map = {}

    def migrate_all(self):
        self._export_legacy_db()
        self._migrate_tenants()
        self._migrate_users()
        self._migrate_roles()
        self._migrate_tokens()

    def dump_catalog(self, path):
        """Generate the contents of a catalog templates file."""
        pass

    def _export_legacy_db(self):
        self._data = export_db(self.db)

    def _migrate_tenants(self):
        for x in self.data['tenants']:
            new_dict = {'description': x.get('desc', ''),
                        'id': x.get('uid', x.get('id')),
                        'enabled': x.get('enabled', True)}
            new_dict['name'] = x.get('name', new_dict.get('id'))


