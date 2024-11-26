# SPDX-FileCopyrightText: 2024 Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
# SPDX-License-Identifier: MIT

import logging
from pathlib import Path
from typing import ClassVar, Any
from base64 import b64decode, b64encode

from pcapng_utils.payload import Payload
from .base import HarEnrichment
from .types import FlowDirection
from .utils import robust_b64decode

logger = logging.getLogger('enrichment')


class ContentDecryption(HarEnrichment):

    ID: ClassVar = 'decryption'

    MIN_LEN_ENCRYPTED_BYTES: int = 8  # at least 16 bytes for AES encrypted data for instance
    MIN_LEN_DECRYPTED_BYTES: int = 2  # e.g. '[]' or '{}'

    MAX_SIZE_DIFF_FRACTION: float = 0.5  # do NOT keep best match if abs. size difference is > 50% of original size

    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        super().__init__(har_data, input_data_file)
        self.cryptography_operations: list[dict] = self.input_data  # type: ignore

    @staticmethod
    def _is_ignored_algorithm(algo: str) -> bool:
        # Message digests, MAC and signatures (could lead to false positives)
        # cf. https://developer.android.com/reference/java/security/MessageDigest
        # cf. https://developer.android.com/reference/java/security/Signature
        # cf. https://developer.android.com/reference/kotlin/javax/crypto/Mac
        algo = algo.upper()
        return (
            algo.startswith('SHA') or algo.startswith('MD5') or
            algo.startswith('DSA') or algo.startswith('ECDSA') or algo.startswith('ED25519') or algo.startswith('EDDSA') or algo.startswith('NONEWITH') or
            algo.startswith('HMAC') or algo.startswith('PBEWITHHMAC') or algo.startswith('AESCMAC')
        )

    @staticmethod
    def _is_asymmetrical_encryption(algo: str) -> bool:
        # cf. https://developer.android.com/reference/javax/crypto/Cipher
        algo = algo.upper()
        return algo.startswith("RSA")

    def _find_decrypted_data(self, encrypted_payload: bytes, encrypted_data_parameter_name: FlowDirection) -> dict:
        """ Find the decrypted data matching the given base64 encoded payload """
        # Fail fast
        if encrypted_data_parameter_name not in {'in', 'out'}:
            raise ValueError(f'Invalid {encrypted_data_parameter_name=}')

        # Ignore payload with less than 8 bytes to avoid false positives and collisions
        len_encrypted_payload = len(encrypted_payload)
        if len_encrypted_payload < self.MIN_LEN_ENCRYPTED_BYTES:
            return {}

        best_match: dict = {}
        best_abs_size_diff: float | None = None  # in number of bytes (absolute)
        hex_encrypted_payload = encrypted_payload.hex()

        # If it's a request, the encrypted data is the output ('out') of the cryptographic primitive,
        # but in input ('in') for a response
        decrypted_data_parameter_name = 'out' if encrypted_data_parameter_name == 'in' else 'in'

        for operation in self.cryptography_operations:
            # Read the cryptographic operation data and try to match
            # - algorithm is ignored (signature, digest, MAC)
            # - unless data for operation is missing/empty/too tiny
            op_algo = operation.get('alg', '')
            if self._is_ignored_algorithm(op_algo):
                continue

            # <!> both encrypted and decrypted data encoded in hexadecimal from the cryptographic primitive data
            op_data = operation.get('data', {})
            op_hex_encrypted_data = op_data.get(encrypted_data_parameter_name, '')
            op_hex_decrypted_data = op_data.get(decrypted_data_parameter_name, '')

            len_op_encrypted_data = len(op_hex_encrypted_data) // 2
            len_op_decrypted_data = len(op_hex_decrypted_data) // 2
            if len_op_encrypted_data < self.MIN_LEN_ENCRYPTED_BYTES or len_op_decrypted_data < self.MIN_LEN_DECRYPTED_BYTES:
                continue

            # Check if the encrypted data is in the payload or vice versa
            if op_hex_encrypted_data in hex_encrypted_payload or hex_encrypted_payload in op_hex_encrypted_data:
                # Compute the size difference between the operation data and the actual payload
                # (operation size is mean of encrypted and decrypted sizes by default, only encrypted size for asymmetric cipher)
                # Minimum size difference is the best match
                len_op = (
                    len_op_encrypted_data if self._is_asymmetrical_encryption(op_algo)
                    else (len_op_encrypted_data + len_op_decrypted_data) / 2
                )
                abs_diff = abs(len_encrypted_payload - len_op)
                if best_abs_size_diff is None or abs_diff < best_abs_size_diff:
                    best_abs_size_diff = abs_diff
                    best_match = {
                        'operation': operation,
                        'hex_decrypted_data': op_hex_decrypted_data,
                        'size_diff_encrypted': len_op_encrypted_data - len_encrypted_payload,
                        'size_diff_decrypted': len_op_decrypted_data - len_encrypted_payload,
                    }

        # The best match was found, prepare the enrichment data
        if not best_match:
            return {}

        assert best_abs_size_diff is not None
        best_abs_size_diff_frac = best_abs_size_diff / len_encrypted_payload
        logger.debug(f'Decrypted content found: abs. size difference = {best_abs_size_diff_frac:.1%} of encrypted size')

        if best_abs_size_diff_frac > self.MAX_SIZE_DIFF_FRACTION:
            logger.debug('Ignoring decrypted content since abs. size diff is too big')
            return {}

        operation = best_match['operation']
        decrypted_bytes = bytes.fromhex(best_match['hex_decrypted_data'])

        return {
            'pid': operation.get('pid', ''),
            'process': operation.get('process', ''),
            'timestamp': operation.get('timestamp', 0.) / 1000.,  # Convert to seconds
            'primitiveParameters': {
                'algorithm': operation['data'].get('alg', ''),
                'key': operation['data'].get('key', ''),
                'iv': operation['data'].get('iv', ''),
            },
            'originalBase64Content': b64encode(encrypted_payload).decode('ascii'),
            'sizeDiffEncrypted': int(best_match['size_diff_encrypted']),
            'sizeDiffDecrypted': int(best_match['size_diff_decrypted']),
            # temp key for data exchange, not stored in HAR
            'decryptedBytes': decrypted_bytes,
        }

    @staticmethod
    def _get_bytes_possibly_from_base64(content: dict[str, str]) -> bytes | None:
        if content.get('encoding') == 'base64':
            return b64decode(content['text'], validate=True)  # always valid standard base64
        try:
            return robust_b64decode(content['text'])  # possibly in base64 (various forms...)
        except (ValueError, UnicodeError):
            return None

    @classmethod
    def _get_request_bytes_and_mime(cls, request: dict) -> tuple[bytes | None, str]:
        # <!> the sender may base64-encode the bytes himself beforehand
        if 'postData' in request:
            return cls._get_bytes_possibly_from_base64(request['postData']), request['postData']['mimeType']
        if '_content' in request:
            return cls._get_bytes_possibly_from_base64(request['_content']), request['_content'].get('mimeType', '')
        return None, ''

    @classmethod
    def _get_response_bytes_and_mime(cls, response: dict) -> tuple[bytes | None, str]:
        # <!> the sender may base64-encode the bytes himself beforehand
        if 'content' in response:
            return cls._get_bytes_possibly_from_base64(response['content']), response['content']['mimeType']
        return None, ''

    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        # Process the request data and attach the decryption data if found
        request = har_entry['request']
        req_bytes, req_mimetype = self._get_request_bytes_and_mime(request)
        if req_bytes:
            enrichment_data = self._find_decrypted_data(req_bytes, 'out')
            if enrichment_data:
                Payload(enrichment_data.pop('decryptedBytes')).update_har_request(request, req_mimetype)
                request['_decryption'] = enrichment_data

        # Process the response data and attach the decryption data if found
        response = har_entry['response']
        resp_bytes, resp_mimetype = self._get_response_bytes_and_mime(response)
        if resp_bytes:
            enrichment_data = self._find_decrypted_data(resp_bytes, 'in')
            if enrichment_data:
                Payload(enrichment_data.pop('decryptedBytes')).update_har_response(response, resp_mimetype)
                response['_decryption'] = enrichment_data
