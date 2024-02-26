import json
import ctypes
import ctypes.wintypes

from urllib.parse import urlencode

winhttp = ctypes.windll.winhttp

WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
WINHTTP_NO_PROXY_NAME = None
WINHTTP_NO_PROXY_BYPASS = None
TLS_10 = 0x00000080
TLS_11 = 0x00000200
WINHTTP_FLAG_ASYNC = 0
WINHTTP_AUTH_TARGET_PROXY = 1
WINHTTP_AUTH_SCHEME_NEGOTIATE = 16
WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW = ctypes.wintypes.DWORD(1)
WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM = ctypes.wintypes.DWORD(0)
WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH = ctypes.wintypes.DWORD(2)
WINHTTP_OPTION_AUTOLOGON_POLICY = 77
WINHTTP_OPTION_SECURITY_FLAGS = 31
WINHTTP_OPTION_HTTP_VERSION = 59
WINHTTP_OPTION_CONNECT_TIMEOUT = 3
WINHTTP_QUERY_RAW_HEADERS = WINHTTP_QUERY_EX_ALL_HEADERS = 21
WINHTTP_QUERY_RAW_HEADERS_CRLF = 22
WINHTTP_QUERY_CONTENT_LENGTH = 5
WINHTTP_QUERY_CUSTOM = 65535
WINHTTP_QUERY_FLAG_WIRE_ENCODING = 16777216
WINHTTP_CALLBACK_FLAG_REDIRECT = 0x00004000
ERROR_INSUFFICIENT_BUFFER = 122
WINHTTP_OPTION_PROXY_USERNAME = 0x1002
WINHTTP_OPTION_PROXY_PASSWORD = 0x1003
WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON = 0x10000000
SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100
SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200
SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x1000
SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x2000
 
errors = {
    6: "ERROR_INVALID_HANDLE",
    ERROR_INSUFFICIENT_BUFFER: "ERROR_INSUFFICIENT_BUFFER",
    12001: "ERROR_WINHTTP_OUT_OF_HANDLES",
    12002: "ERROR_WINHTTP_TIMEOUT",
    12004: "ERROR_WINHTTP_INTERNAL_ERROR",
    12005: "ERROR_WINHTTP_INVALID_URL",
    12006: "ERROR_WINHTTP_UNRECOGNIZED_SCHEME",
    12007: "ERROR_WINHTTP_NAME_NOT_RESOLVED",
    12009: "ERROR_WINHTTP_INVALID_OPTION",
    12011: "ERROR_WINHTTP_OPTION_NOT_SETTABLE",
    12012: "ERROR_WINHTTP_SHUTDOWN",
    12015: "ERROR_WINHTTP_LOGIN_FAILURE",
    12017: "ERROR_WINHTTP_OPERATION_CANCELLED",
    12018: "ERROR_WINHTTP_INCORRECT_HANDLE_TYPE",
    12019: "ERROR_WINHTTP_INCORRECT_HANDLE_STATE",
    12029: "ERROR_WINHTTP_CANNOT_CONNECT",
    12030: "ERROR_WINHTTP_CONNECTION_ERROR",
    12032: "ERROR_WINHTTP_RESEND_REQUEST",
    12037: "ERROR_WINHTTP_SECURE_CERT_DATE_INVALID",
    12038: "ERROR_WINHTTP_SECURE_CERT_CN_INVALID",
    12044: "ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED",
    12045: "ERROR_WINHTTP_SECURE_INVALID_CA",
    12057: "ERROR_WINHTTP_SECURE_CERT_REV_FAILED",
    12100: "ERROR_WINHTTP_CANNOT_CALL_BEFORE_OPEN",
    12101: "ERROR_WINHTTP_CANNOT_CALL_BEFORE_SEND",
    12102: "ERROR_WINHTTP_CANNOT_CALL_AFTER_SEND",
    12103: "ERROR_WINHTTP_CANNOT_CALL_AFTER_OPEN",
    12150: "ERROR_WINHTTP_HEADER_NOT_FOUND",
    12152: "ERROR_WINHTTP_INVALID_SERVER_RESPONSE",
    12153: "ERROR_WINHTTP_INVALID_HEADER",
    12154: "ERROR_WINHTTP_INVALID_QUERY_REQUEST",
    12155: "ERROR_WINHTTP_HEADER_ALREADY_EXISTS",
    12156: "ERROR_WINHTTP_REDIRECT_FAILED",
    12157: "ERROR_WINHTTP_SECURE_CHANNEL_ERROR",
    12166: "ERROR_WINHTTP_BAD_AUTH_PROXY_SCRIPT",
    12167: "ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT",
    12169: "ERROR_WINHTTP_SECURE_INVALID_CERT",
    12170: "ERROR_WINHTTP_SECURE_CERT_REVOKED",
    12172: "ERROR_WINHTTP_NOT_INITIALIZED",
    12175: "ERROR_WINHTTP_SECURE_FAILURE",
    12178: "ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR",
    12179: "ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE",
    12180: "ERROR_WINHTTP_AUTODETECTION_FAILED",
    12181: "ERROR_WINHTTP_HEADER_COUNT_EXCEEDED",
    12182: "ERROR_WINHTTP_HEADER_SIZE_OVERFLOW",
    12183: "ERROR_WINHTTP_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW",
    12184: "ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW",
    12185: "ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY",
    12186: "ERROR_WINHTTP_CLIENT_CERT_NO_ACCESS_PRIVATE_KEY"
}

securityLevels = {
    "low": WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW,
    "medium": WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
    "high": WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH
}

class WINHTTP_EXTENDED_HEADER(ctypes.Structure):
    # _anonymous_ = (
    #     "WINHTTP_HEADER_NAME", 
    #     "WINHTTP_HEADER_VALUE"
    # )
    class _NAME_UNION(ctypes.Union):
        _fields_ = [
            ("pwszName", ctypes.c_wchar_p),
            ("pszName", ctypes.c_char_p)
        ]

    class _VALUE_UNION(ctypes.Union):
        _fields_ = [
            ("pwszValue", ctypes.c_wchar_p),
            ("pszValue", ctypes.c_char_p)
        ]

    _anonymous_ = ("name", "value")
    _fields_ = [
        ("name", _NAME_UNION),
        ("value", _VALUE_UNION)
    ]

class HTTP_VERSION_INFO(ctypes.Structure):
    _fields_ = [
        ("dwMajorVersion", ctypes.wintypes.DWORD),
        ("dwMinorVersion", ctypes.wintypes.DWORD)
    ]

winhttp.WinHttpOpen.restype = ctypes.wintypes.HANDLE
winhttp.WinHttpOpen.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
]

winhttp.WinHttpConnect.restype = ctypes.wintypes.HANDLE
winhttp.WinHttpConnect.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCWSTR,
    ctypes.c_uint,
    ctypes.wintypes.DWORD
]

winhttp.WinHttpSetStatusCallback.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD)
]

winhttp.WinHttpOpenRequest.restype = ctypes.wintypes.HANDLE
winhttp.WinHttpOpenRequest.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD
]

winhttp.WinHttpSendRequest.restype = ctypes.wintypes.BOOL
winhttp.WinHttpSendRequest.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p
]

winhttp.WinHttpReceiveResponse.restype = ctypes.wintypes.BOOL
winhttp.WinHttpReceiveResponse.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID
]

winhttp.WinHttpQueryHeaders.restype = ctypes.wintypes.BOOL
winhttp.WinHttpQueryHeaders.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.wintypes.LPDWORD,
    ctypes.wintypes.LPDWORD
]

winhttp.WinHttpAddRequestHeaders.restype = ctypes.wintypes.BOOL
winhttp.WinHttpAddRequestHeaders.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD
]

winhttp.WinHttpQueryOption.restype = ctypes.wintypes.BOOL
winhttp.WinHttpQueryOption.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.wintypes.LPDWORD
]

winhttp.WinHttpQueryDataAvailable.restype = ctypes.wintypes.BOOL
winhttp.WinHttpQueryDataAvailable.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPDWORD
]

winhttp.WinHttpReadData.restype = ctypes.wintypes.BOOL
winhttp.WinHttpReadData.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPDWORD
]

winhttp.WinHttpCloseHandle.restype = ctypes.wintypes.BOOL
winhttp.WinHttpCloseHandle.argtypes = [
    ctypes.wintypes.HANDLE
]

winhttp.WinHttpSetOption.restype = ctypes.wintypes.BOOL
winhttp.WinHttpSetOption.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD
]

winhttp.WinHttpSetCredentials.restype = ctypes.wintypes.BOOL
winhttp.WinHttpSetCredentials.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPVOID
]

def _raise_error(error_code):
    if error_code in errors:
        raise WindowsError(f"[{error_code}] {errors[error_code]}")
    else:
        raise WindowsError(f"[{error_code}] Unknown error")

class Request(object):
    def __init__(self, url: str, userAgent: str=None, securityLevel: str="medium", headers: dict=None, http_version: float=None, method: str=None):
        if not isinstance(url, str):
            raise ValueError("'url' must be of type 'str'")
        self.__dict__.update(
            {
                "url": url,
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                "securityLevel": "medium",
                "headers": None,
                "http_version": None,
                "method": "GET"
            }
        )
        if isinstance(userAgent, str):
            self.userAgent = userAgent
        
        if method and method in ["GET", "PUT", "POST"]:
            self.method = method
        
        if securityLevel.lower() in ["low", "medium", "high"]:
            self.securityLevel = securityLevel
        
        if isinstance(headers, dict):
            self.headers = headers
        elif headers:
            raise ValueError("'headers' must be type 'dict'")

        if isinstance(http_version, float) and http_version in [1.0, 1.1]:
            self.http_version = http_version

class opener(object):
    def __init__(self, target, data: bytes=None, timeout: int=None, verify: bool=True):
        if isinstance(target, str):
            self.url = target
            userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            securityLevel = securityLevels["medium"]
            headers = None
            http_version = None
            method = None
        elif isinstance(target, Request):
            self.url = target.url
            userAgent = target.userAgent
            securityLevel = securityLevels[target.securityLevel.lower()]
            headers = target.headers
            http_version = target.http_version
            method = target.method

        if data:
            if isinstance(data, str):
                data = data.encode()
            elif isinstance(data, bytes):
                pass
            elif data:
                raise ValueError("'data' must be type 'bytes' or 'str'")
            if not method:
                method = "POST"
        
        if not isinstance(timeout, int):
            timeout = None
        
        if headers:
            headers = "\r\n".join([f"{k}: {v}" for k,v in headers.items()])
        
        spliturl = self.url.split('http://')[-1].split('https://')[-1].split('/')
        hostname = spliturl[0]
        path = "/" + "/".join(spliturl[1:])

        hInternet = winhttp.WinHttpOpen(
            ctypes.wintypes.LPCWSTR(userAgent),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 
            WINHTTP_FLAG_ASYNC
        )

        if not hInternet or int(hInternet) < 1:
            _raise_error(ctypes.GetLastError())

        callback_type = ctypes.CFUNCTYPE(
            None, 
            ctypes.wintypes.HANDLE, 
            ctypes.POINTER(ctypes.wintypes.DWORD), 
            ctypes.wintypes.DWORD, 
            ctypes.c_void_p, 
            ctypes.wintypes.DWORD
        )

        callback = callback_type(self.redirect_callback)

        hResult = winhttp.WinHttpSetStatusCallback(
            hInternet,
            callback,
            WINHTTP_CALLBACK_FLAG_REDIRECT,
            None
        )

        if hResult == -1:
            raise OSError("Failed to set redirect callback with 'WINHTTP_INVALID_STATUS_CALLBACK'")

        hConnect = winhttp.WinHttpConnect(
            hInternet,
            hostname,
            0,
            0
        )

        if not hConnect or int(hConnect) < 1:
            _raise_error(ctypes.GetLastError())

        if self.url.startswith("https://"):
            iFlag = ctypes.wintypes.DWORD(0x00800000)
        else:
            iFlag = ctypes.wintypes.DWORD(0x00000000)
        
        hRequest = winhttp.WinHttpOpenRequest(
            ctypes.c_void_p(hConnect),
            ctypes.c_wchar_p(method),
            ctypes.c_wchar_p(path),
            ctypes.c_wchar_p(None),
            ctypes.c_wchar_p(None),
            ctypes.c_wchar_p(None),
            iFlag
        )

        if not hRequest or hRequest < 1:
            _raise_error(ctypes.GetLastError())

        if not verify:
            certFlags = ctypes.wintypes.DWORD(SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
            result = winhttp.WinHttpSetOption(
                hRequest,
                WINHTTP_OPTION_SECURITY_FLAGS,
                ctypes.byref(certFlags),
                ctypes.sizeof(certFlags)
            )
            if not result:
                _raise_error(ctypes.GetLastError())
        
        if timeout:
            dwTimeout = ctypes.wintypes.DWORD(int(timeout * 1000))
            result = winhttp.WinHttpSetOption(
                hRequest,
                WINHTTP_OPTION_CONNECT_TIMEOUT,
                ctypes.byref(dwTimeout),
                ctypes.sizeof(dwTimeout)
            )
            if not result:
                _raise_error(ctypes.GetLastError())

        result = winhttp.WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_AUTOLOGON_POLICY,
            ctypes.byref(securityLevel),
            ctypes.sizeof(securityLevel)
        )

        if not result:
            _raise_error(ctypes.GetLastError())

        if headers:
            winhttp.WinHttpAddRequestHeaders(
                hRequest,
                headers,
                -1,
                WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON
            )

        if http_version in [1.0, 1.1]:
            old_http_version = HTTP_VERSION_INFO()
            old_http_version_len = ctypes.wintypes.DWORD(ctypes.sizeof(old_http_version))
            result = winhttp.WinHttpQueryOption(
                hRequest,
                WINHTTP_OPTION_HTTP_VERSION,
                ctypes.byref(old_http_version),
                ctypes.byref(old_http_version_len)
            )
            httpVersion = HTTP_VERSION_INFO()
            httpVersion.dwMajorVersion = int(http_version)
            httpVersion.dwMinorVersion = int(str(http_version).split('.')[-1])
            result = winhttp.WinHttpSetOption(
                hRequest,
                WINHTTP_OPTION_HTTP_VERSION,
                ctypes.byref(httpVersion),
                ctypes.sizeof(httpVersion)
            )
            if not result:
                _raise_error(ctypes.GetLastError())

        if method in ["PUT", "POST"]:
            dataArray = ctypes.create_string_buffer(data)
            pData = ctypes.byref(dataArray)
            dataLen = len(data)
        else:
            pData = ctypes.c_void_p()
            dataLen = 0

        result = winhttp.WinHttpSendRequest(
            hRequest,
            None,
            0,
            pData,
            dataLen,
            dataLen,
            0
        )

        if not result:
            _raise_error(ctypes.GetLastError())

        result = winhttp.WinHttpReceiveResponse(
            hRequest,
            None
        )

        if not result:
            _raise_error(ctypes.GetLastError())

        try:
            headersEx = False
            winhttp.WinHttpQueryHeadersEx.restype = ctypes.wintypes.DWORD
            headerStruct = WINHTTP_EXTENDED_HEADER()
            pHeaderStruct = ctypes.pointer(headerStruct)
            headerCount = ctypes.wintypes.DWORD()
            headerIndex = ctypes.wintypes.PDWORD()
            headerSize = ctypes.c_ulong(0)
            result = winhttp.WinHttpQueryHeadersEx(
                ctypes.wintypes.HANDLE(hRequest),
                ctypes.wintypes.DWORD(WINHTTP_QUERY_EX_ALL_HEADERS),
                ctypes.c_ulonglong(0),
                ctypes.c_uint(0),
                headerIndex,
                None,
                None,
                ctypes.byref(headerSize),
                ctypes.byref(pHeaderStruct),
                ctypes.byref(headerCount)
            )
            if headerSize.value > 0:
                headerStruct = (WINHTTP_EXTENDED_HEADER * headerCount.value)()
                pHeaderStruct = ctypes.pointer(headerStruct)
                headerBuffer = (ctypes.c_ubyte * headerSize.value)()
                result = winhttp.WinHttpQueryHeadersEx(
                    ctypes.wintypes.HANDLE(hRequest),
                    ctypes.wintypes.DWORD(WINHTTP_QUERY_EX_ALL_HEADERS),
                    ctypes.c_ulonglong(0),
                    ctypes.c_uint(0),
                    headerIndex,
                    None,
                    ctypes.byref(headerBuffer),
                    ctypes.byref(headerSize),
                    ctypes.byref(pHeaderStruct),
                    ctypes.byref(headerCount)
                )
            if result:
                _raise_error(ctypes.GetLastError())
            self.responseHeaders = {hStruct.pwszName: hStruct.pwszValue  for hStruct in pHeaderStruct.contents}
        except AttributeError as e:
            headerSize = ctypes.wintypes.DWORD(0)
            result = winhttp.WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                None,
                None,
                headerSize,
                None
            )
            if not result and ctypes.GetLastError() == ERROR_INSUFFICIENT_BUFFER:
                headerBuffer = (ctypes.c_ubyte * headerSize.value)()
                result = winhttp.WinHttpQueryHeaders(
                    hRequest,
                    WINHTTP_QUERY_RAW_HEADERS_CRLF,
                    None,
                    ctypes.byref(headerBuffer),
                    ctypes.wintypes.DWORD(ctypes.sizeof(headerBuffer)),
                    None
                )
            if not result and not headersEx:
                _raise_error(ctypes.GetLastError())
            rawHeaders = bytes(headerBuffer).decode('utf-16').rstrip('\0').split('\r\n')[1:-2]
            self.responseHeaders = {header.split(':')[0]:header.split(':')[1].lstrip() for header in rawHeaders}

        bytesAvailable = ctypes.c_ulong(0)
        result = winhttp.WinHttpQueryDataAvailable(
            hRequest,
            bytesAvailable
        )

        if not result:
            _raise_error(ctypes.GetLastError())

        payload = b""

        while bytesAvailable.value:
            readBuffer = (ctypes.c_ubyte * bytesAvailable.value)()
            bytesToRead = bytesAvailable.value
            bytesRead = ctypes.wintypes.DWORD(0)
            result = winhttp.WinHttpReadData(
                hRequest,
                readBuffer,
                bytesToRead,
                bytesRead
            )
            if not result:
                _raise_error(ctypes.GetLastError())
            payload += bytes(readBuffer)
            result = winhttp.WinHttpQueryDataAvailable(
                hRequest,
                bytesAvailable
            )
            if not result:
                _raise_error(ctypes.GetLastError())

        self.raw = payload

        if http_version in [1.0, 1.1]:
            result = winhttp.WinHttpSetOption(
                hRequest,
                WINHTTP_OPTION_HTTP_VERSION,
                ctypes.byref(old_http_version),
                ctypes.sizeof(old_http_version)
            )
            if not result:
                _raise_error(ctypes.GetLastError())

        result = winhttp.WinHttpCloseHandle(
            hInternet
        )

        hInternet = None

        if not result:
            _raise_error(ctypes.GetLastError())

    def read(self):
        return self.raw

    def json(self):
        if not self.raw:
            raise BaseException("No response data exists")
        return json.loads(self.raw)

    def redirect_callback(self, hInternet, dwContext, dwInternetStatus, lpvStatusInformation, dwStatusInformationLength):
        pUrl = ctypes.cast(lpvStatusInformation, ctypes.wintypes.LPWSTR)
        self.url = pUrl.value
