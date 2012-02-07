# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2011 OpenStack LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Module that contains all object models

The models are used to hold Keystone 'business' objects and their validation,
serialization, and backend interaction code.

The models are based off of python's dict.

The uses supported are:
    # can be initialized with static properties
    tenant = Tenant(name='A1000')

    # handles writing to correct backend
    tenant.save()

    # static properties
    id = tenant.id
    tenant = None

    # Acts as a dict
    tenant is a dict
    tenant.dict points to the data dict (i.e. tenant["tenant"])

    # can be retrieved by static property
    tenant_by_name = Tenant.get(name='A1000')

    # can be retrieved  by id default, so name not needed
    tenant_by_id = Tenant.get(id)
    assertIsEquals(tenant_by_id, tenant_by_name)

    # handles serialization
    print tenant_by_id
    print tenant_by_id.to_json()    # Keystone latest contract
    print tenant_by_id.to_json_20()  # Keystone 2.0 contract

    Serialization routines can take hints in this format:
        {
            "contract_attributes": ["id", "name", ...],
            "types": [("id", int), (...)]
        }
        attribute/value can be:
        contract_attributes: list of contract attributes (see initializer)
            format is a list of attributes names (ex ['id', 'name'])
        types: list of attribute/type mappings
            format is a list of name/type tuples (ex [('id', int)])
        tags: list of attributes that go into XML tags
            format is a list of attribute names(ex ['description']
        maps: list of attributes to rename
            format is from/to values (ex {'serviceId": "service_id",})
    Default hints can be stored in the class as cls.hints
"""

import json
from lxml import etree


class AttrDict(dict):
    """Lets us do setattr and getattr since dict does not allow it"""
    pass


class Resource(AttrDict):
    """ Base class for models

    Provides basic functionality that can be overridden """

    hints = {}
    xmlns = None

    def __init__(self, *args, **kw):
        """ Initialize object
        kwargs contain static properties
        """
        super(Resource, self).__init__(*args, **kw)
        # attributes that can be used as attributes. Example:
        #    tenant.id  - here id is a contract attribute
        super(Resource, self).__setattr__("contract_attributes", [])
        if kw:
            self.contract_attributes.extend(kw.keys())
            for name, value in kw.iteritems():
                self[name] = value

    #
    # model properties
    #
    # Override built-in classes to allow for user.id (as well as user["id"])
    # for attributes defined in the Keystone contract
    #
    def __repr__(self):
        return "<%s(%s)>" % (self.__class__.__name__, ', '.join(['%s=%s' %
                (attrib, self[attrib].__repr__()) for attrib in
                self.contract_attributes]))

    def __str__(self):
        """Returns string representation including the class name."""
        return str(self.to_dict())

    def __getattr__(self, name):
        """ Supports reading contract attributes (ex. tenant.id)

        This should only be called if the original call did not match
        an attribute (Python's rules)"""
        if name in self.contract_attributes:
            if name in self:
                return self[name]
            return None
        elif name == 'desc':  # TODO(zns): deprecate this
            # We need to maintain this compatibility with this nasty attribute
            # until we're done refactoring
            return self.description
        else:
            if hasattr(super(Resource, self), name):
                return getattr(super(Resource, self), name)
            else:
                raise AttributeError("'%s' not found on object of class '%s'"
                                     % (name, self.__class__.__name__))

    def __setattr__(self, name, value):
        """ Supports setting contract attributes (ex. tenant.name = 'A1') """

        if name in self.contract_attributes:
            # Put those into the dict (and not as attrs)
            if value is not None:
                self[name] = value
        else:
            super(Resource, self).__setattr__(name, value)

    def __getitem__(self, name):
        if name in self.contract_attributes:
            if super(Resource, self).__contains__(name):
                return super(Resource, self).__getitem__(name)
            return None
        elif name == 'desc':  # TODO(zns): deprecate this
            # We need to maintain this compatibility with this nasty attribute
            # until we're done refactoring
            return self.description
        elif name == self.__class__.__name__.lower():
            # Supports using dict syntax to access the attributes of the
            # class. Ex: Resource(id=1)['resource']['id']
            return self
        else:
            return super(Resource, self).__getitem__(name)

    def __contains__(self, key):
        if key in self.contract_attributes:
            return True
        return super(Resource, self).__contains__(key)

    #
    # Serialization Functions - may be moved to a different class
    #
    def to_dict(self, model_name=None, hints=None):
        """ For compatibility with logic.types """
        if model_name is None:
            model_name = self.__class__.__name__.lower()
        result = self.strip_null_fields(self.copy())
        if hints is None:
            hints = self.hints
        if hints:
            if "types" in hints:
                Resource.apply_type_mappings(
                    result,
                    hints["types"])
            if "maps" in hints:
                Resource.apply_name_mappings(
                    result,
                    hints["maps"])
        return {model_name: result}


    #
    # Validation calls
    #
    def validate(self):
        """ Validates object attributes. Raises error if object not valid

        This calls inspect() in fail_fast mode, so it gets back the first
        validation error and raises it. It is up to the code in inspect()
        to determine what validations take precedence and are returned
        first

        :returns: True if no validation errors raise"""
        errors = self.inspect(fail_fast=True)
        if errors:
            raise errors[0][0](errors[0][1])
        return True

    #
    # Formatting, hint processing functions
    #

    @staticmethod
    def strip_null_fields(dict_object):
        """ Strips null fields from dict"""
        for k, v in dict_object.items():
            if v is None:
                del dict_object[k]
        return dict_object

    @staticmethod
    def apply_type_mappings(target, type_mappings):
        """Applies type mappings to dict values"""
        if type_mappings:
            for name, type in type_mappings:
                if type is int:
                    target[name] = int(target[name])
                elif issubclass(type, basestring):
                    # Move sub to string
                    if name in target:
                        value = target[name]
                        if isinstance(value, dict):
                            value = value[0]
                        if value:
                            target[name] = str(value)
                elif type is bool:
                    target[name] = str(target[name]).lower() not in ['0',
                                                                     'false']
                else:
                    raise NotImplementedError("Model type mappings cannot \
                                handle '%s' types" % type.__name__)



def is_empty_string(value):
    """
    Checks whether string is empty.
    """
    if value is None:
        return True
    if not isinstance(value, basestring):
        return False
    if len(value.strip()) == 0:
        return True
    return False


class Service(Resource):
    """ Service model """
    def __init__(self, id=None, name=None, type=None, description=None,
                 owner_id=None, *args, **kw):
        super(Service, self).__init__(id=id, name=name, type=type,
                                      description=description,
                                      owner_id=owner_id, *args, **kw)
        # pylint: disable=E0203
        if isinstance(self.id, int):
            self.id = str(self.id)


class Services(object):
    "A collection of services."

    def __init__(self, values, links):
        self.values = values
        self.links = links


class Tenant(Resource):
    """ Tenant model """
    # pylint: disable=E0203,C0103
    def __init__(self, id=None, name=None, description=None, enabled=None,
                 *args, **kw):
        super(Tenant, self).__init__(id=id, name=name,
#                                      description=description, enabled=enabled,
                                      *args, **kw)
        if isinstance(self.id, int):
            self.id = str(self.id)
#        if isinstance(self.enabled, basestring):
#            self.enabled = self.enabled.lower() == 'true'


class User(Resource):
    """ User model

    Attribute Notes:
    default_tenant_id (formerly tenant_id): this attribute can be enabled or
        disabled by configuration. When enabled, any authentication call
        without a tenant gets authenticated to this tenant.
    """
    # pylint: disable=R0913
    def __init__(self, id=None, password=None, name=None,
                 #email=None,
                 *args, **kw):
        super(User, self).__init__(id=id, password=password, name=name,
                        #email=email,
                        *args, **kw)


class EndpointTemplate(Resource):
    """ EndpointTemplate model """
    # pylint: disable=R0913
    def __init__(self, id=None, region=None, service_id=None, public_url=None,
            admin_url=None, internal_url=None, enabled=None, is_global=None,
            version_id=None, version_list=None, version_info=None, *args,
            **kw):
        super(EndpointTemplate, self).__init__(id=id, region=region,
                service_id=service_id, public_url=public_url,
                admin_url=admin_url, internal_url=internal_url,
                enabled=enabled, is_global=is_global, version_id=version_id,
                version_list=version_list, version_info=version_info, *args,
                **kw)


class Endpoint(Resource):
    """ Endpoint model """
    # pylint: disable=R0913
    def __init__(self, id=None, endpoint_template_id=None, tenant_id=None,
            *args, **kw):
        super(Endpoint, self).__init__(id=id, tenant_id=tenant_id,
                endpoint_template_id=endpoint_template_id, *args, **kw)


class Role(Resource):
    """ Role model """
    hints = {"maps":
                {"userId": "user_id",
                "roleId": "role_id",
                "serviceId": "service_id",
                "tenantId": "tenant_id"},
            "contract_attributes": ['id', 'name', 'service_id',
                                           'tenant_id', 'description'],
            "types": [('id', basestring), ('service_id', basestring)],
        }
    xmlns = "http://docs.openstack.org/identity/api/v2.0"

    def __init__(self, id=None, name=None, description=None, service_id=None,
                 tenant_id=None, *args, **kw):
        super(Role, self).__init__(id=id, name=name,
                                   description=description,
                                   service_id=service_id,
                                   tenant_id=tenant_id,
                                    *args, **kw)
        # pylint: disable=E0203
        if isinstance(self.id, int):
            self.id = str(self.id)
        # pylint: disable=E0203
        if isinstance(self.service_id, int):
            self.service_id = str(self.service_id)


class Roles(object):
    "A collection of roles."

    def __init__(self, values, links):
        self.values = values
        self.links = links


class Token(Resource):
    """ Token model """
    def __init__(self, id=None, user_id=None, expires=None, tenant_id=None,
            *args, **kw):
        super(Token, self).__init__(id=id, user_id=user_id, expires=expires,
                                    tenant_id=tenant_id, *args, **kw)


class UserRoleAssociation(Resource):
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
        super(UserRoleAssociation, self).__init__(user_id=user_id,
                                    role_id=role_id, tenant_id=tenant_id,
                                    *args, **kw)
        if isinstance(self.user_id, int):
            # pylint: disable=E0203
            self.user_id = str(self.user_id)
        if isinstance(self.tenant_id, int):
            self.tenant_id = str(self.tenant_id)


class Credentials(Resource):
    # pylint: disable=R0913
    def __init__(self, id=None, user_id=None, tenant_id=None, type=None,
            key=None, secret=None, *args, **kw):
        super(Credentials, self).__init__(id=id, user_id=user_id,
            tenant_id=tenant_id, type=type, key=key, secret=secret, *args,
            **kw)
