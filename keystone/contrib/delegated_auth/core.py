"""Extensions supporting delegated auth."""


from keystone.common import controller
from keystone.common import dependency
from keystone.common import manager
from keystone.common import oauth
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import token


CONF = config.CONF

@dependency.provider('delegated_auth')
class Manager(manager.Manager):
    """Default pivot point for the delegated auth credentials backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.delegated_auth.driver)


class DelegatedAuthExtension(wsgi.ExtensionRouter):
    """API Endpoints for the Delegated Auth extension.

    The goal of this extension is to allow third-party service providers
    to acquire tokens with a limited subset of a user's roles for acting
    on behalf of that user. This is done using an oauth-similar flow and
    api.



    """



    def add_routes(self, mapper):
        da_controller = DelegatedAuthController()
        # validation
        mapper.connect(
            '/da/',
            controller=da_controller,
            action='authenticate',
            conditions=dict(method=['POST']))

        # crud
        mapper.connect(
            '/users/{user_id}/credentials/OS-EC2',
            controller=da_controller,
            action='create_credential',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/users/{user_id}/credentials/OS-EC2',
            controller=da_controller,
            action='get_credentials',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users/{user_id}/credentials/OS-EC2/{credential_id}',
            controller=da_controller,
            action='get_credential',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users/{user_id}/credentials/OS-EC2/{credential_id}',
            controller=da_controller,
            action='delete_credential',
            conditions=dict(method=['DELETE']))


@dependency.requires('catalog_api', 'ec2_api')
class Ec2Controller(controller.V2Controller):
    def check_signature(self, creds_ref, credentials):
        signer = ec2_utils.Ec2Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        if utils.auth_str_equal(credentials['signature'], signature):
            return
        # NOTE(vish): Some libraries don't use the port when signing
        #             requests, so try again without port.
        elif ':' in credentials['signature']:
            hostname, _port = credentials['host'].split(':')
            credentials['host'] = hostname
            signature = signer.generate(credentials)
            if not utils.auth_str_equal(credentials.signature, signature):
                raise exception.Unauthorized(message='Invalid EC2 signature.')
        else:
            raise exception.Unauthorized(message='EC2 signature not supplied.')

    def authenticate(self, context, credentials=None, ec2Credentials=None):
        """Validate a signed EC2 request and provide a token.

        Other services (such as Nova) use this **admin** call to determine
        if a request they signed received is from a valid user.

        If it is a valid signature, an openstack token that maps
        to the user/tenant is returned to the caller, along with
        all the other details returned from a normal token validation
        call.

        The returned token is useful for making calls to other
        OpenStack services within the context of the request.

        :param context: standard context
        :param credentials: dict of ec2 signature
        :param ec2Credentials: DEPRECATED dict of ec2 signature
        :returns: token: openstack token equivalent to access key along
                         with the corresponding service catalog and roles
        """

        # FIXME(ja): validate that a service token was used!

        # NOTE(termie): backwards compat hack
        if not credentials and ec2Credentials:
            credentials = ec2Credentials

        if 'access' not in credentials:
            raise exception.Unauthorized(message='EC2 signature not supplied.')

        creds_ref = self._get_credentials(context,
                                          credentials['access'])
        self.check_signature(creds_ref, credentials)

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        token_id = uuid.uuid4().hex
        tenant_ref = self.identity_api.get_project(
            context=context,
            tenant_id=creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(
            context=context,
            user_id=creds_ref['user_id'])
        metadata_ref = self.identity_api.get_metadata(
            context=context,
            user_id=user_ref['id'],
            tenant_id=tenant_ref['id'])

        # Validate that the auth info is valid and nothing is disabled
        token.validate_auth_info(self, context, user_ref, tenant_ref)

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        roles = metadata_ref.get('roles', [])
        if not roles:
            raise exception.Unauthorized(message='User not valid for tenant.')
        roles_ref = [self.identity_api.get_role(context, role_id)
                     for role_id in roles]

        catalog_ref = self.catalog_api.get_catalog(
            context=context,
            user_id=user_ref['id'],
            tenant_id=tenant_ref['id'],
            metadata=metadata_ref)

        token_ref = self.token_api.create_token(
            context, token_id, dict(id=token_id,
                                    user=user_ref,
                                    tenant=tenant_ref,
                                    metadata=metadata_ref))

        # TODO(termie): i don't think the ec2 middleware currently expects a
        #               full return, but it contains a note saying that it
        #               would be better to expect a full return
        return token.controllers.Auth.format_authenticate(
            token_ref, roles_ref, catalog_ref)

    def create_credential(self, context, user_id, tenant_id):
        """Create a secret/access pair for use with ec2 style auth.

        Generates a new set of credentials that map the the user/tenant
        pair.

        :param context: standard context
        :param user_id: id of user
        :param tenant_id: id of tenant
        :returns: credential: dict of ec2 credential
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)

        self._assert_valid_user_id(context, user_id)
        self._assert_valid_project_id(context, tenant_id)

        cred_ref = {'user_id': user_id,
                    'tenant_id': tenant_id,
                    'access': uuid.uuid4().hex,
                    'secret': uuid.uuid4().hex}
        self.ec2_api.create_credential(context, cred_ref['access'], cred_ref)
        return {'credential': cred_ref}

    def get_credentials(self, context, user_id):
        """List all credentials for a user.

        :param context: standard context
        :param user_id: id of user
        :returns: credentials: list of ec2 credential dicts
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        self._assert_valid_user_id(context, user_id)
        return {'credentials': self.ec2_api.list_credentials(context, user_id)}

    def get_credential(self, context, user_id, credential_id):
        """Retrieve a user's access/secret pair by the access key.

        Grab the full access/secret pair for a given access key.

        :param context: standard context
        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: credential: dict of ec2 credential
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        self._assert_valid_user_id(context, user_id)
        creds = self._get_credentials(context, credential_id)
        return {'credential': creds}

    def delete_credential(self, context, user_id, credential_id):
        """Delete a user's access/secret pair.

        Used to revoke a user's access/secret pair

        :param context: standard context
        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: bool: success
        """
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
            self._assert_owner(context, user_id, credential_id)

        self._assert_valid_user_id(context, user_id)
        self._get_credentials(context, credential_id)
        return self.ec2_api.delete_credential(context, credential_id)

    def _get_credentials(self, context, credential_id):
        """Return credentials from an ID.

        :param context: standard context
        :param credential_id: id of credential
        :raises exception.Unauthorized: when credential id is invalid
        :returns: credential: dict of ec2 credential.
        """
        creds = self.ec2_api.get_credential(context,
                                            credential_id)
        if not creds:
            raise exception.Unauthorized(message='EC2 access key not found.')
        return creds

    def _assert_identity(self, context, user_id):
        """Check that the provided token belongs to the user.

        :param context: standard context
        :param user_id: id of user
        :raises exception.Forbidden: when token is invalid

        """
        try:
            token_ref = self.token_api.get_token(
                context=context,
                token_id=context['token_id'])
        except exception.TokenNotFound as e:
            raise exception.Unauthorized(e)

        if token_ref['user'].get('id') != user_id:
            raise exception.Forbidden('Token belongs to another user')

    def _is_admin(self, context):
        """Wrap admin assertion error return statement.

        :param context: standard context
        :returns: bool: success

        """
        try:
            self.assert_admin(context)
            return True
        except exception.Forbidden:
            return False

    def _assert_owner(self, context, user_id, credential_id):
        """Ensure the provided user owns the credential.

        :param context: standard context
        :param user_id: expected credential owner
        :param credential_id: id of credential object
        :raises exception.Forbidden: on failure

        """
        cred_ref = self.ec2_api.get_credential(context, credential_id)
        if not user_id == cred_ref['user_id']:
            raise exception.Forbidden('Credential belongs to another user')

    def _assert_valid_user_id(self, context, user_id):
        """Ensure a valid user id.

        :param context: standard context
        :param user_id: expected credential owner
        :raises exception.UserNotFound: on failure

        """
        user_ref = self.identity_api.get_user(
            context=context,
            user_id=user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)

    def _assert_valid_project_id(self, context, tenant_id):
        """Ensure a valid tenant id.

        :param context: standard context
        :param tenant_id: expected tenant
        :raises exception.ProjectNotFound: on failure

        """
        tenant_ref = self.identity_api.get_project(
            context=context,
            tenant_id=tenant_id)
        if not tenant_ref:
            raise exception.ProjectNotFound(project_id=tenant_id)
