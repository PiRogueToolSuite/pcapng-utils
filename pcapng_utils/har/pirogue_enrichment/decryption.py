# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
from typing import Literal, Any

from ...payload import Payload
from . import HarEnrichment
from .utils import base64_to_hex

logger = logging.getLogger('enrichment')


class ContentDecryption(HarEnrichment):
    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        super().__init__(har_data, input_data_file)
        self.cryptography_operations: list[dict] = self.input_data  # type: ignore

        if not self.can_enrich:
            logger.warning('HAR enrichment with encryption information cannot be performed, skip.')

    def _find_decrypted_data(self, base64_encoded_payload: str, encrypted_data_parameter_name: Literal['in', 'out']) -> dict:
        """ Find the decrypted data matching the given base64 encoded payload """
        best_match: dict = {}
        size_diff: int = 2 ** 31 - 1

        # Fail first
        if encrypted_data_parameter_name not in ('in', 'out'):
            raise ValueError(f'Invalid {encrypted_data_parameter_name=}')

        # Ignore payload with less than 8 bytes to avoid false positives and collisions
        hex_encoded_payload = base64_to_hex(base64_encoded_payload)
        if not hex_encoded_payload or len(hex_encoded_payload) < 16:
            return {}

        # If it's a request, the encrypted data is the output ('out') of the cryptographic primitive,
        # but in input ('in') for a response
        decrypted_data_parameter_name = 'out' if encrypted_data_parameter_name == 'in' else 'in'

        for operation in self.cryptography_operations:
            # Read the cryptographic operation data and continue if the data is missing or empty
            # (both encrypted and decrypted data encoded in hexadecimal from the cryptographic primitive data)
            operation_data = operation.get('data', {})
            hex_encoded_encrypted_data = operation_data.get(encrypted_data_parameter_name, '')
            hex_encoded_decrypted_data = operation_data.get(decrypted_data_parameter_name, '')

            # Continue if the encrypted or decrypted data is missing or empty
            if not hex_encoded_encrypted_data or not hex_encoded_decrypted_data:
                continue

            # Check if the encrypted data is in the payload or vice versa
            if hex_encoded_encrypted_data in hex_encoded_payload or hex_encoded_payload in hex_encoded_encrypted_data:
                # Compute the size difference between the encrypted data and the payload
                # Minimum size difference is the best match
                diff = abs(len(hex_encoded_encrypted_data) - len(hex_encoded_payload))
                if diff < size_diff:
                    size_diff = diff
                    best_match = {
                        'operation': operation,
                        'hex_encoded_decrypted_data': hex_encoded_decrypted_data,
                        'size_diff': size_diff / 2  # Convert to length in bytes
                    }

        # The best match was found, prepare the enrichment data
        if not best_match:
            return {}

        logger.debug('Decrypted content found')

        operation = best_match['operation']
        decrypted_bytes = bytes.fromhex(best_match['hex_encoded_decrypted_data'])

        return {
            'pid': operation.get('pid', ''),
            'process': operation.get('process', ''),
            'timestamp': operation.get('timestamp', 0.) / 1000.,  # Convert to seconds
            'primitiveParameters': {
                'iv': operation['data'].get('iv', ''),
                'algorithm': operation['data'].get('alg', ''),
                'key': operation['data'].get('key', ''),
            },
            'originalBase64Content': base64_encoded_payload,
            'sizeDiff': int(best_match['size_diff']),
            # temp key for data exchange, not stored in HAR
            'decryptedBytes': decrypted_bytes,
        }

    @staticmethod
    def _get_request_b64_data_and_mime(request: dict) -> tuple[str | None, str]:
        if 'postData' in request and request['postData'].get('encoding') == 'base64':
            return request['postData']['text'], request['postData']['mimeType']
        if '_content' in request and request['_content'].get('encoding') == 'base64':
            return request['_content']['text'], request['_content'].get('mimeType', '')
        return None, ''

    @staticmethod
    def _get_response_b64_data_and_mime(response: dict) -> tuple[str | None, str]:
        if 'content' in response and response['content'].get('encoding', '') == 'base64':
            return response['content']['text'], response['content']['mimeType']
        return None, ''

    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        # Process the request data and attach the decryption data if found
        request = har_entry['request']
        req_b64, req_mimetype = self._get_request_b64_data_and_mime(request)
        if req_b64:
            enrichment_data = self._find_decrypted_data(req_b64, 'out')
            if enrichment_data:
                decrypted_payload = Payload(enrichment_data.pop('decryptedBytes'))
                request['_decryption'] = enrichment_data
                # remove original request data keys & fill with new ones
                request.pop('postData', None)
                request.pop('_content', None)
                request.pop('_requestBodyStatus', None)
                decrypted_payload.fill_har_request(request, req_mimetype)

        # Process the response data and attach the decryption data if found
        response = har_entry['response']
        resp_b64, resp_mimetype = self._get_response_b64_data_and_mime(response)
        if resp_b64:
            enrichment_data = self._find_decrypted_data(resp_b64, 'in')
            if enrichment_data:
                decrypted_payload = Payload(enrichment_data.pop('decryptedBytes'))
                response['_decryption'] = enrichment_data
                decrypted_payload.fill_har_response(response, resp_mimetype)
