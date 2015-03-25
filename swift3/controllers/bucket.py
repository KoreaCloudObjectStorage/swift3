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

from copy import copy

from swift.common.wsgi import make_pre_authed_request
from swift.common.http import HTTP_OK
from swift.common.utils import json

from swift3.controllers.base import Controller
from swift3.controllers.acl import handle_acl_header
from swift3.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from swift3.response import HTTPOk, S3NotImplemented, InvalidArgument, \
    MalformedXML, InvalidLocationConstraint, NoSuchBucket
from swift3.cfg import CONF
from swift3.utils import LOGGER

MAX_PUT_BUCKET_BODY_SIZE = 4194304  # 4MB


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.get_response(self.app)

        return HTTPOk(headers=resp.headers)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """

        max_keys = req.get_validated_param('max-keys', CONF.max_bucket_listing)
        # TODO: Separate max_bucket_listing and default_bucket_listing
        max_keys = min(max_keys, CONF.max_bucket_listing)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        query = {
            'format': 'json',
            'limit': max_keys + 1,
        }
        if 'marker' in req.params:
            query.update({'marker': req.params['marker']})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})
        if 'delimiter' in req.params:
            query.update({'delimiter': req.params['delimiter']})
        if 'lifecycle' in req.params:
            query.update({'lifecycle': req.params['lifecycle']})
        if 'lifecycle_rule' in req.params:
            query.update({'lifecycle_rule': req.params['lifecycle_rule']})

        resp = req.get_response(self.app, query=query)

        if 'X-Lifecycle-Response' in resp.headers:
            return resp

        objects = json.loads(resp.body)

        elem = Element('ListBucketResult')
        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')

        # in order to judge that truncated is valid, check whether
        # max_keys + 1 th element exists in swift.
        is_truncated = max_keys > 0 and len(objects) > max_keys
        objects = objects[:max_keys]

        if is_truncated and 'delimiter' in req.params:
            if 'name' in objects[-1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[-1]['name']
            if 'subdir' in objects[-1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[-1]['subdir']

        SubElement(elem, 'MaxKeys').text = str(max_keys)

        if 'delimiter' in req.params:
            SubElement(elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(elem, 'EncodingType').text = encoding_type

        SubElement(elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for o in objects:
            if 'name' not in o:
                continue

            oresp = req.get_response(self.app, 'HEAD', req.container_name,
                                     o['name'])
            if 'X-Object-Meta-Glacier' in oresp.headers:
                o['class'] = 'GLACIER'
            else:
                o['class'] = 'STANDARD'

        for o in objects:
            if 'subdir' not in o:
                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'] + 'Z'
                SubElement(contents, 'ETag').text = o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                SubElement(contents, 'StorageClass').text = o['class']
                owner = SubElement(contents, 'Owner')
                SubElement(owner, 'ID').text = req.user_id
                SubElement(owner, 'DisplayName').text = req.user_id
                SubElement(contents, 'StorageClass').text = 'STANDARD'

        for o in objects:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)

        if req.query_string in ('lifecycle', 'lifecycle_rule'):
            xml = None

        if xml:
            # check location
            try:
                elem = fromstring(xml, 'CreateBucketConfiguration')
                location = elem.find('./LocationConstraint').text
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                LOGGER.error(e)
                raise

            if location != CONF.location:
                # Swift3 cannot support multiple reagions now.
                raise InvalidLocationConstraint()

        if 'HTTP_X_AMZ_ACL' in req.environ:
            handle_acl_header(req)

        resp = req.get_response(self.app)
        if 'X-Lifecycle-Response' not in resp.headers:
            resp.status = HTTP_OK
        resp.location = '/' + req.container_name
        return resp

    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        if req.params:
            return req.get_response(self.app)

        original_resp = req.get_response(self.app)

        """
        Deleting _segments container and its objects for remaining segments
        """
        head_req = copy(req)
        container = head_req.container_name
        head_req.container_name = container + '_segments'
        try:
            more_result = True
            d = ''
            seg = None
            while more_result:
                resp = head_req.get_response(self.app, 'GET',
                                             query={'format': 'json',
                                                    'marker': d})
                segments = json.loads(resp.body)
                for seg in segments:
                    head_req.get_response(self.app, 'DELETE', obj=seg['name'])
                if seg:
                    d = seg['name']
                    seg = None
                else:
                    more_result = False

            resp = head_req.get_response(self.app, 'DELETE')
        except NoSuchBucket as e:
            # If _segments bucket is not exist, exception will be occurence.
            pass

        """
        Deleting container lifecycle
        """
        head_req.container_name = container
        head_req.get_response(self.app, 'DELETE', query={'lifecycle': '',
                                                         'force_delete': ''})

        return original_resp

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise S3NotImplemented()
