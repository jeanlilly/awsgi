from urllib.parse import urlencode, unquote
from base64 import b64encode, b64decode
from io import BytesIO
import itertools
import collections
import sys
import gzip

ONE_MTU_SIZE = 1400


def convert_str(s):
    return s.decode('utf-8') if isinstance(s, bytes) else s


def convert_byte(b):
    return b.encode('utf-8', errors='strict') if (
        isinstance(b, str)) else b


def convert_b64(s):
    return b64encode(s).decode('ascii')


try:
    service_version = open("./VERSION").read().strip()
except Exception:
    service_version = "undefined"

__all__ = 'response',


class StartResponse(object):
    def __init__(self, base64_content_types=None, use_gzip=False):
        '''
        Args:
            base64_content_types (set): Set of HTTP Content-Types which should
            return a base64 encoded body. Enables returning binary content from
            API Gateway.
        '''
        self.status = 500
        self.status_line = '500 Internal Server Error'
        self.headers = [
            ("version", service_version)
        ]
        self.use_gzip = use_gzip
        self.chunks = collections.deque()
        self.base64_content_types = set(base64_content_types or []) or set()

    def __call__(self, status, headers, exc_info=None):
        self.status_line = status
        self.status = int(status.split()[0])
        self.headers[:] = headers
        return self.chunks.append

    def use_binary_response(self, headers, body):
        content_type = headers.get('Content-Type')

        if content_type and ';' in content_type:
            content_type = content_type.split(';')[0]
        return content_type in self.base64_content_types

    def use_gzip_response(self, headers, body):
        content_type = headers.get('Content-Type')
        return self.use_gzip and content_type in {
            "application/javascript",
            "application/json",
            "text/css",
            "text/html",
            "text/plain",
            "text/html",
            "image/svg+xml",
            "font/otf",
            "font/ttf"
        } and len(body) > ONE_MTU_SIZE

    def build_body(self, headers, output):
        totalbody = b''.join(itertools.chain(
            self.chunks, output,
        ))

        is_gzip = self.use_gzip_response(headers, totalbody)
        is_b64 = self.use_binary_response(headers, totalbody)
        print(f"IS_GZIP = {is_gzip}")
        if is_gzip:
            totalbody = gzip.compress(totalbody)
            headers["Content-Encoding"] = "gzip"
            is_b64 = True

        if is_b64:
            converted_output = convert_b64(totalbody)
        else:
            converted_output = convert_str(totalbody)

        return {
            'isBase64Encoded': is_b64,
            'body': converted_output,
        }

    def response(self, output):
        headers = dict(self.headers)

        rv = {
            'statusCode': self.status,
            'headers': headers,
        }
        rv.update(self.build_body(headers, output))
        return rv


class StartResponse_GW(StartResponse):
    def response(self, output):
        rv = super(StartResponse_GW, self).response(output)

        rv['statusCode'] = str(rv['statusCode'])

        return rv


class StartResponse_ELB(StartResponse):
    def response(self, output):
        rv = super(StartResponse_ELB, self).response(output)

        rv['statusCode'] = int(rv['statusCode'])
        rv['statusDescription'] = self.status_line

        return rv


def environ_v2(event, context):
    """Prepare the WSGI environment from the Lambda event+context"""
    # Check if format version is in v2, used for determining where to retrieve http method and path
    is_v2 = "2.0" in event.get("version", {})

    body = event.get("body", "") or ""  # Outside things can set the value to None

    if event.get("isBase64Encoded", False):
        body = b64decode(body)

    # FIXME: Flag the encoding in the headers <- this is old note, IDK what it is supposed to mean
    body = convert_byte(body)

    # Use get() to access queryStringParameter field without throwing error if it doesn't exist
    query_string = event.get("queryStringParameters", {}) or {}  # Outside things can set the value to None
    if "multiValueQueryStringParameters" in event and event["multiValueQueryStringParameters"]:
        query_string = []
        for key in event["multiValueQueryStringParameters"]:
            for value in event["multiValueQueryStringParameters"][key]:
                query_string.append((key, value))

    use_environ = {
        # Get http method from within requestContext.http field in V2 format
        "REQUEST_METHOD": event["requestContext"]["http"]["method"] if is_v2 else event["httpMethod"],
        "SCRIPT_NAME": "",
        "SERVER_NAME": "",
        "SERVER_PORT": "",
        "PATH_INFO": unquote(event["requestContext"]["http"]["path"] if is_v2 else event["path"]),
        "QUERY_STRING": urlencode(query_string),
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP": "on",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.input": BytesIO(body),
        "wsgi.errors": sys.stderr,  # PONDER: is there a smarter stream we can use ? some logging facility ?
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "wsgi.url_scheme": "",
        "awsgi.event": event,
        "awsgi.context": context,
    }
    headers = event.get("headers", {}) or {}  # Outside things can set the value to None
    for key, val in headers.items():
        key = key.upper().replace("-", "_")

        if key == "CONTENT_TYPE":
            use_environ["CONTENT_TYPE"] = val
        elif key == "HOST":
            use_environ["SERVER_NAME"] = val
        elif key == "X_FORWARDED_FOR":
            use_environ["REMOTE_ADDR"] = val.split(", ")[0]
        elif key == "X_FORWARDED_PROTO":
            use_environ["wsgi.url_scheme"] = val
        elif key == "X_FORWARDED_PORT":
            use_environ["SERVER_PORT"] = val

        use_environ["HTTP_" + key] = val

    return use_environ


def environ(event, context):
    body = event.get('body', '') or ''

    if event.get('isBase64Encoded', False):
        body = b64decode(body)
    # FIXME: Flag the encoding in the headers
    body = convert_byte(body)

    environ = {
        'REQUEST_METHOD': event['httpMethod'],
        'SCRIPT_NAME': '',
        'SERVER_NAME': '',
        'SERVER_PORT': '',
        'PATH_INFO': event['path'],
        'QUERY_STRING': urlencode(event['queryStringParameters'] or {}),
        'REMOTE_ADDR': '127.0.0.1',
        'CONTENT_LENGTH': str(len(body)),
        'HTTP': 'on',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'wsgi.version': (1, 0),
        'wsgi.input': BytesIO(body),
        'wsgi.errors': sys.stderr,
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
        'wsgi.url_scheme': '',
        'awsgi.event': event,
        'awsgi.context': context,
    }
    headers = event.get('headers', {}) or {}
    for k, v in headers.items():
        k = k.upper().replace('-', '_')

        if k == 'CONTENT_TYPE':
            environ['CONTENT_TYPE'] = v
        elif k == 'ACCEPT_ENCODING':
            environ['ACCEPT_ENCODING'] = v
        elif k == 'HOST':
            environ['SERVER_NAME'] = v
        elif k == 'X_FORWARDED_FOR':
            environ['REMOTE_ADDR'] = v.split(', ')[0]
        elif k == 'X_FORWARDED_PROTO':
            environ['wsgi.url_scheme'] = v
        elif k == 'X_FORWARDED_PORT':
            environ['SERVER_PORT'] = v

        environ['HTTP_' + k] = v

    return environ


def select_impl(event, context):
    if 'elb' in event.get('requestContext', {}):
        return environ_v2, StartResponse_ELB
    else:
        return environ_v2, StartResponse_GW


def response(app, event, context, base64_content_types=None):

    environ, StartResponse = select_impl(event, context)

    use_gzip = bool("gzip" in event.get("headers", {}).get('accept-encoding', ""))
    sr = StartResponse(base64_content_types=base64_content_types, use_gzip=use_gzip)
    output = app(environ(event, context), sr)
    response = sr.response(output)

    return response
