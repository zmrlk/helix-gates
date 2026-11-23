"""Loopback-only synthetic OIDC provider. No real identity or upstream access."""
import base64
import http.server
import json
import ssl
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlencode, urlparse


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def der_value(data, offset=0):
    tag, length = data[offset:offset+2]; offset += 2
    if length & 128:
        count = length & 127
        length = int.from_bytes(data[offset:offset+count], 'big'); offset += count
    return tag, data[offset:offset+length], offset+length


def public_jwk(openssl, key):
    der = subprocess.check_output([openssl, 'rsa', '-in', key, '-RSAPublicKey_out', '-outform', 'DER'], stderr=subprocess.DEVNULL)
    _, sequence, _ = der_value(der)
    _, modulus, end = der_value(sequence)
    _, exponent, _ = der_value(sequence, end)
    return dict(kty='RSA', use='sig', alg='RS256', kid='synthetic', n=b64(modulus.lstrip(b'\0')), e=b64(exponent))


def authorization_prefix(path):
    for suffix in ('/protocol/openid-connect/auth', '/authorize', '/login', '/auth'):
        if path.endswith(suffix): return path.removesuffix(suffix)
    return None


def serve(port, cert, key, openssl):
    issuer = 'https://127.0.0.1:'+str(port)
    jwk = public_jwk(openssl, key)
    codes = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def send_response(self, code, message=None):
            print(json.dumps(dict(method=self.command,url=issuer+urlparse(self.path).path,status=code,source='stub')),flush=True)
            super().send_response(code,message)
        def respond(self, data, code=200):
            payload = json.dumps(data).encode()
            self.send_response(code); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def do_GET(self):
            parsed = urlparse(self.path); query = parse_qs(parsed.query)
            if parsed.path.endswith('/.well-known/openid-configuration'):
                provider=issuer+parsed.path.removesuffix('/.well-known/openid-configuration')
                self.respond(dict(issuer=provider, authorization_endpoint=provider+'/authorize', token_endpoint=provider+'/token',
                                  jwks_uri=provider+'/jwks', userinfo_endpoint=provider+'/userinfo', response_types_supported=['code'],
                                  subject_types_supported=['public'], id_token_signing_alg_values_supported=['RS256'],
                                  end_session_endpoint=provider+'/end_session',
                                  token_endpoint_auth_methods_supported=['client_secret_basic','client_secret_post','none'],
                                  code_challenge_methods_supported=['S256']))
            elif parsed.path.endswith('/jwks'): self.respond(dict(keys=[jwk]))
            elif parsed.path.endswith('/userinfo'): self.respond(dict(sub='synthetic-user', name='Synthetic User', email='user@example.test', email_verified=True))
            elif parsed.path.endswith(('/logout','/end_session','/protocol/openid-connect/logout')):
                redirect=query.get('post_logout_redirect_uri',[''])[0]
                if redirect and urlparse(redirect).hostname in ('127.0.0.1','localhost'):
                    self.send_response(302); self.send_header('Location',redirect); self.end_headers()
                else: self.respond(dict(logged_out=True))
            elif authorization_prefix(parsed.path) is not None:
                redirect = query.get('redirect_uri',[''])[0]
                if urlparse(redirect).hostname not in ('127.0.0.1','localhost'): return self.respond(dict(error='invalid_request'),400)
                import secrets
                code=secrets.token_hex(16); query['_issuer']=[issuer+authorization_prefix(parsed.path)]; codes[code]=query
                self.send_response(302); self.send_header('Location',redirect+('&' if '?' in redirect else '?')+urlencode(dict(code=code,state=query.get('state',[''])[0]))); self.end_headers()
            else: self.respond(dict(error='not_found'),404)
        def do_POST(self):
            if urlparse(self.path).path.endswith(('/logout','/end_session','/userinfo')): return self.do_GET()
            if not urlparse(self.path).path.endswith('/token'): return self.respond(dict(error='not_found'),404)
            query=parse_qs(self.rfile.read(min(int(self.headers.get('Content-Length',0)),10000)).decode())
            auth=codes.pop(query.get('code',[''])[0],None)
            if auth is None: return self.respond(dict(error='invalid_grant'),400)
            claims=dict(iss=auth['_issuer'][0],sub='synthetic-user',aud=auth.get('client_id',['helix-synthetic'])[0],iat=int(time.time()),exp=int(time.time())+300,name='Synthetic User',email='user@example.test')
            if auth.get('nonce'): claims['nonce']=auth['nonce'][0]
            signing=(b64(json.dumps(dict(alg='RS256',kid='synthetic')).encode())+'.'+b64(json.dumps(claims).encode())).encode()
            signature=subprocess.check_output([openssl,'dgst','-sha256','-sign',key],input=signing)
            self.respond(dict(access_token='synthetic-access',token_type='Bearer',expires_in=300,id_token=signing.decode()+'.'+b64(signature)))
    server=http.server.HTTPServer(('127.0.0.1',port),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()


if __name__ == '__main__': serve(int(sys.argv[1]), *sys.argv[2:])
