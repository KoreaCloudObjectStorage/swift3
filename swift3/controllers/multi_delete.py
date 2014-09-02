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

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import Element, SubElement, fromstring, tostring, \
    DocumentInvalid
from swift3.response import HTTPOk, S3NotImplemented, NoSuchKey, \
    ErrorResponse, MalformedXML

MAX_MULTI_DELETE_BODY_SIZE = 61365


class MultiObjectDeleteController(Controller):
    """
    Handles Delete Multiple Objects, which is logged as a MULTI_OBJECT_DELETE
    operation in the S3 server log.
    """
    @bucket_operation
    def POST(self, req):
        """
        Handles Delete Multiple Objects.
        """
        def object_key_iter(xml):
            try:
                elem = fromstring(xml, 'Delete')
            except DocumentInvalid:
                raise MalformedXML()

            for obj in elem.iterchildren('Object'):
                key = obj.find('./Key').text
                version = obj.find('./VersionId')
                if version is not None:
                    version = version.text

                yield (key, version)

        elem = Element('DeleteResult')

        xml = req.xml(MAX_MULTI_DELETE_BODY_SIZE)

        quiet = fromstring(xml, 'Delete').find('Quiet')
        if quiet is not None:
            quiet = quiet.text.lower()

        req.headers['Content-Length'] = 0

        for key, version in object_key_iter(xml):
            if version is not None:
                # TODO: delete the specific version of the object
                raise S3NotImplemented()

            req.object_name = key

            try:
                req.get_response(self.app, method='DELETE')
            except NoSuchKey:
                pass
            except ErrorResponse as e:
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                SubElement(error, 'Code').text = e.__class__.__name__
                SubElement(error, 'Message').text = e._msg
                continue

            if quiet == 'true':
                continue

            deleted = SubElement(elem, 'Deleted')
            SubElement(deleted, 'Key').text = key

        body = tostring(elem)

        return HTTPOk(body=body)
