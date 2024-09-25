from __future__ import annotations
import binascii
import json
import warnings
from typing import TYPE_CHECKING, Any
from .algorithms import Algorithm, get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import DecodeError, InvalidAlgorithmError, InvalidSignatureError, InvalidTokenError
from .utils import base64url_decode, base64url_encode
from .warnings import RemovedInPyjwt3Warning
if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys


class PyJWS:
    header_typ = 'JWT'

    def __init__(self, algorithms: (list[str] | None)=None, options: (dict[
        str, Any] | None)=None) ->None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(
            self._algorithms)
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]
        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) ->None:
        """
        Registers a new Algorithm for use when creating and verifying tokens.
        """
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) ->None:
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        Throws KeyError if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(f"The algorithm '{alg_id}' is not registered.")
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) ->list[str]:
        """
        Returns a list of supported values for the 'alg' parameter.
        """
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) ->Algorithm:
        """
        For a given string name, return the matching Algorithm object.

        Example usage:

        >>> jws_obj.get_algorithm_by_name("RS256")
        """
        if alg_name not in self._algorithms:
            raise InvalidAlgorithmError(f"Algorithm '{alg_name}' could not be found")
        return self._algorithms[alg_name]

    def get_unverified_header(self, jwt: (str | bytes)) ->dict[str, Any]:
        """Returns back the JWT header parameters as a dict()

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        if isinstance(jwt, str):
            jwt = jwt.encode('utf-8')

        try:
            header_segment = jwt.split(b'.')[0]
            header_data = base64url_decode(header_segment)
            header = json.loads(header_data.decode('utf-8'))
        except (ValueError, TypeError, binascii.Error) as e:
            raise DecodeError(f"Invalid header padding: {str(e)}")

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        return header


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
