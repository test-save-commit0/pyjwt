import json
import platform
import sys
from typing import Dict
from . import __version__ as pyjwt_version
try:
    import cryptography
    cryptography_version = cryptography.__version__
except ModuleNotFoundError:
    cryptography_version = ''


def info() ->Dict[str, Dict[str, str]]:
    """
    Generate information for a bug report.
    Based on the requests package help utility module.
    """
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
        },
        "dependencies": {
            "pyjwt": pyjwt_version,
            "cryptography": cryptography_version,
        },
    }


def main() ->None:
    """Pretty-print the bug information as JSON."""
    print(json.dumps(info(), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
