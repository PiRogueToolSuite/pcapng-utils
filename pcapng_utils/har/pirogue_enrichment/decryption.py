# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import base64
import logging
from pathlib import Path

from pcapng_utils.har.pirogue_enrichment import HarEnrichment
from pcapng_utils.har.pirogue_enrichment.utils import base64_to_hex

logger = logging.getLogger('enrichment')


class ContentDecryption(HarEnrichment):
    def __init__(self, har_data: dict, input_data_file: Path):
        super().__init__(har_data, input_data_file)
        self.cryptography_operations: list[dict] = self.input_data

        if not self.can_enrich:
            logger.warning('HAR enrichment with encryption information cannot be performed, skip.')

    def _find_decrypted_data(self, base64_encoded_payload: str, direction: str) -> dict:
        """ Find the decrypted data matching the given base64 encoded payload """
        enrichment_data: dict = {}
        best_match: dict = {}
        size_diff: int = 2 ** 31 - 1

        # Fail first
        if direction not in ('in', 'out'):
            raise ValueError(f'Invalid communication direction: {direction}')

        # Ignore payload with less than 8 bytes to avoid false positives and collisions
        hex_encoded_payload = base64_to_hex(base64_encoded_payload)
        if not hex_encoded_payload or len(hex_encoded_payload) < 16:
            return enrichment_data

        # If it's a request (direction == 'out'), the encrypted data is the output (out) of the cryptographic primitive,
        # input (in) otherwise
        encrypted_data_parameter_name = direction
        decrypted_data_parameter_name = 'out' if direction == 'in' else 'in'

        for operation in self.cryptography_operations:
            # Read the cryptographic operation data and continue if the data is missing or empty
            operation_data = operation.get('data', {})
            if not operation_data or not operation_data.get(decrypted_data_parameter_name):
                continue

            # Read both encrypted and decrypted data encoded in hexadecimal from the cryptographic primitive data
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
                        'size_diff': size_diff / 2  # Convert to bytes
                    }

        # The best match was found, prepare the enrichment data
        if best_match:
            operation = best_match['operation']
            hex_encoded_decrypted_data = best_match['hex_encoded_decrypted_data']

            # Try to decode the raw data to a UTF-8 string
            encoding = ''
            decoded_data = bytes.fromhex(hex_encoded_decrypted_data)
            try:
                decoded_data = decoded_data.decode('utf-8')
            except (UnicodeDecodeError, Exception):
                decoded_data = base64.urlsafe_b64encode(decoded_data)
                encoding = 'base64'

            logger.debug(f'Decrypted content found')

            enrichment_data = {
                'pid': operation.get('pid', ''),
                'process': operation.get('process', ''),
                'timestamp': operation.get('timestamp', 0.) / 1000.,  # Convert to seconds
                'primitiveParameters': {
                    'iv': operation['data'].get('iv', ''),
                    'algorithm': operation['data'].get('alg', ''),
                    'key': operation['data'].get('key', ''),
                },
                'sizeDiff': int(best_match['size_diff']),
                'encoding': encoding,
                'originalContent': base64_encoded_payload,
                'decryptedContent': decoded_data
            }
        return enrichment_data

    def enrich(self):
        if not self.can_enrich:
            return
        for har_entry in self.har_data['log']['entries']:
            # Process the request data and attach the decryption data if found
            request = har_entry.get('request', {})
            if 'postData' in request and request['postData'].get('encoding', '') == 'base64':
                base64_encoded_data = request['postData'].get('text', '')
                # No data, skip
                if not base64_encoded_data:
                    continue
                enrichment_data = self._find_decrypted_data(base64_encoded_data, 'out')
                if enrichment_data:
                    request['_decryption'] = enrichment_data
                    request['postData']['text'] = enrichment_data.get('decryptedContent')
                    request['postData']['encoding'] = enrichment_data.get('encoding')

            # Process the response data and attach the decryption data if found
            response = har_entry.get('response', {})
            if 'content' in response and response['content'].get('encoding', '') == 'base64':
                base64_encoded_data = response['content'].get('text', '')
                if not base64_encoded_data:
                    continue
                enrichment_data = self._find_decrypted_data(base64_encoded_data, 'out')
                if enrichment_data:
                    response['_decryption'] = enrichment_data
                    response['content']['text'] = enrichment_data.get('decryptedContent')
                    response['content']['encoding'] = enrichment_data.get('encoding')
