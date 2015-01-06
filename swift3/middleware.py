# Copyright (c) 2010-2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following operations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

import rfc822

from cStringIO import StringIO

from swift.common.utils import get_logger
from swift.common.middleware.formpost import _parse_attrs
from swift.common.middleware.formpost import _iter_requests

from swift3.exception import NotS3Request
from swift3.request import Request
from swift3.response import HTTPOk, ErrorResponse, InternalError, MethodNotAllowed, \
    ResponseBase
from swift3.cfg import CONF

# List of  sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions ', 'website'
])

#: The size of data to read from the form at any given time.
READ_CHUNK_SIZE = 4096


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""

    def __init__(self, app, *args, **kwargs):
        self.app = app
        self.logger = get_logger(CONF, log_route='swift3')
        self.storage_domain = CONF.get('storage_domain', 'example.com')

    def __call__(self, env, start_response):
        try:
            # CORS
            resp = self.cors(env)

            if not resp:
                # SubdomainCallingFormat
                self.domain_remap(env)

                # POST
                self.post_request(env)

                req = Request(env)

                if req.is_service_request:
                    env['swift.source'] = 'account'
                elif req.is_bucket_request:
                    env['swift.source'] = 'container'
                elif req.is_object_request:
                    env['swift.source'] = 'object'

                resp = self.handle_request(req)
        except NotS3Request:
            resp = self.app
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            resp = err_resp
        except Exception, e:
            self.logger.exception(e)
            resp = InternalError(reason=e)

        if isinstance(resp, ResponseBase) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        return resp(env, start_response)

    def cors(self, env):
        method = env['REQUEST_METHOD'] if 'REQUEST_METHOD' in env else None
        if method != 'OPTIONS':
            return

        resp = HTTPOk()
        resp.headers = dict()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, HEAD'
        resp.headers['Access-Control-Allow-Headers'] = 'content-type'
        resp.headers['Access-Control-Max-Age'] = '3000'
        resp.headers['Vary'] = 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method'
        resp.headers['Content-Length'] = '0'

        return resp

    def domain_remap(self, env):
        if not self.storage_domain:
            return

        key = None
        if 'HTTP_HOST' in env:
            key = 'HTTP_HOST'
        elif 'SERVER_NAME' in env:
            key = 'SERVER_NAME'

        if not key:
            return

        given_domain = env[key]
        if not given_domain:
            return

        # remove port
        if ':' in given_domain:
            given_domain = given_domain.rsplit(':', 1)[0]
            if not given_domain:
                return

        dotted_storage_domain = '.' + self.storage_domain
        if not given_domain.endswith(dotted_storage_domain):
            return

        bucket_name = given_domain[:-len(dotted_storage_domain)]
        if not bucket_name:
            return

        env['PATH_INFO'] = '/' + bucket_name + env['PATH_INFO']
        env['RAW_PATH_INFO'] = env['PATH_INFO']
        env[key] = env[key][len(bucket_name) + 1:]

        self.logger.debug('Calling Swift3 Middleware - Domain is remapped')


    def post_request(self, env):
        if env.get('REQUEST_METHOD') != 'POST':
            return

        content_type, attrs = _parse_attrs(env.get('CONTENT_TYPE') or '')
        if content_type != 'multipart/form-data' or 'boundary' not in attrs:
            return

        attributes = self._translate_form(env, attrs['boundary'])

        del env['CONTENT_TYPE']

        env['REQUEST_METHOD'] = 'PUT'

        env_key = 'HTTP_AUTHORIZATION'
        if 'awsaccesskeyid' in attributes and 'signature' in attributes:
            env[env_key] = 'AWS ' + attributes['awsaccesskeyid'] + ':' + attributes['signature']

        env_key = 'POLICY'
        if 'policy' in attributes:
            env[env_key] = attributes['policy']

        env_key = 'PATH_INFO'
        if 'key' in attributes:
            env[env_key] += attributes['key'].lstrip('/')
            env['RAW_PATH_INFO'] = env[env_key]

        env_key = 'CONTENT_LENGTH'
        if 'file' in attributes:
            data = attributes['file']
            env['wsgi.input'] = StringIO(data)
            env[env_key] = str(len(data))

    def _translate_form(self, env, boundary):
        attributes = dict()

        for fp in _iter_requests(env['wsgi.input'], boundary):
            hdrs = rfc822.Message(fp, 0)
            disp, attrs = _parse_attrs(hdrs.getheader('Content-Disposition', ''))
            if disp != 'form-data':
                continue

            data = ''
            while True:
                chunk = fp.read(READ_CHUNK_SIZE)
                if not chunk:
                    break
                data += chunk

            if 'name' in attrs:
                attributes[attrs['name'].lower()] = data

        return attributes

    def handle_request(self, req):
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        controller = req.controller(self.app)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            raise MethodNotAllowed(req.method,
                                   req.controller.resource_type())

        return res


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    CONF.update(global_conf)
    CONF.update(local_conf)

    return Swift3Middleware
