"""Exception defination
"""

class HostCertificateError(Exception):
    """This exception indicates that the https connection is timed out
    """
    def __init__(self, message):
        print("Error:", message)


class IssuerError(Exception):
    """This exception indicates that the https connection is timed out
    """
    def __init__(self, message):
        print("Error:", message)


class OCSPError(Exception):
    """This exception indicates that the https connection is timed out
    """
    def __init__(self, message):
        print("Error:", message)
