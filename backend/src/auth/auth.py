import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'fsnd-sharing.auth0.com'    # 'udacity-fsnd.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_api'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes (different than standard aborts)
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
def get_token_auth_header():
    token = request.headers.get('Authorization', None)
    if not token:
        # If no header, .get above returns None
        raise AuthError({
            'code': 'missing_auth_header',
            'description': 'Missing Authorization header'
        }, 401)
    
    # Token should return a list, with first part "Bearer" and second part the actual token
    parts = token.split()

    # Check first part is bearer
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_auth_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    # Check for missing token (only one element to list) or extra elements
    if len(parts) != 2:
        raise AuthError({
            'code': 'invalid_auth_header',
            'description': 'Auth header invalid.  Must contain bearer token.'
        }, 401)
    
    # If we get here, take the token as-is
    token = parts[1]
    return token


def verify_decode_jwt(token):
    '''
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    NOTE: urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
    '''
    # Get the public keys for RSA from Auth0 here:
    json_url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(json_url.read())
    unverified_header = jwt.get_unverified_header(token)    # Gets the header, but hasn't verified anything (don't trust it!)
    
    # We need to search for the RSA public key id ("kid") that matches the public keys
    # over at the Auth0.com/well-known/jwks.json link
    
    # Example of a header for one of our tokens:
    # unverified_header = {
    #     "alg": "RS256",
    #     "typ": "JWT",
    #     "kid": "Jyh1-4Bv8DT-dLVtnbI58"
    # }

    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    # Iterate searching for a match
    # Example of what's in the Auth0 well-known public key info:
    # {"keys":[{"alg":"RS256","kty":"RSA","use":"sig","n":"w9CF0v8rEww9B4NaiyMUPJ_-sIKEeWxjSh6JamI3-qZ_hSfZqorcm1hcp7gbTrhG8BLHpzx82xuS_PfV_aiCVjjLngacW1xdQD32UlglxEpoi6LKYM9mLDPJRWgOIFwO-DWLKruNhDwc3AXKT5-9ejdk0Gx0mPGO-vkqjGmNPZyI-KzrZrPswC14ypYtQPfXsS5VRakS_DBzwRnBRcPJMFWS3vX3iF0vG1RXGQ48HT7yDh2949NcBjjxYloIgSm-WhgrEbgQQ_rQpSSZKVmmQ4scYbmdMagteIV2VdyJ5BDEt2TVmls-Tvdf9JOj13Bv-hAkwj5yDA6nOJ-QCVaWuQ","e":"AQAB","kid":"Jyh1-4Bv8DT-dLVtnbI58","x5t":"7QlBTRbEJ133POejU9QVtZ4Weo8","x5c":["MIIDATCCAemgAwIBAgIJInNp0lgnhR/BMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMTE2ZzbmQtam9lbC5hdXRoMC5jb20wHhcNMjAwNTA0MjEyNTAwWhcNMzQwMTExMjEyNTAwWjAeMRwwGgYDVQQDExNmc25kLWpvZWwuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw9CF0v8rEww9B4NaiyMUPJ/+sIKEeWxjSh6JamI3+qZ/hSfZqorcm1hcp7gbTrhG8BLHpzx82xuS/PfV/aiCVjjLngacW1xdQD32UlglxEpoi6LKYM9mLDPJRWgOIFwO+DWLKruNhDwc3AXKT5+9ejdk0Gx0mPGO+vkqjGmNPZyI+KzrZrPswC14ypYtQPfXsS5VRakS/DBzwRnBRcPJMFWS3vX3iF0vG1RXGQ48HT7yDh2949NcBjjxYloIgSm+WhgrEbgQQ/rQpSSZKVmmQ4scYbmdMagteIV2VdyJ5BDEt2TVmls+Tvdf9JOj13Bv+hAkwj5yDA6nOJ+QCVaWuQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTzaPKVp59kjbd+2kE+F6E04jqOhTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBABoWZrJ4/lJA1eJL0Y4FQODZzqSmjzVUDPo26pL5gdGNUXcG1/xgc06hR4Qm+T1YVnOI1hPseMPfxexJBKTe5b9XsIICV7w18cekK/B/T48Qjl/M83Dc3Zcihs4jVMqEzkKuXasLokTEOKZOwTaa/1pKT1KWFF7EnFuCd6v2m8M9RvNDzsDlXO5mU1td58jjaWRtm/2a/6fe7QlgM4bRpBBqGzEgSjnqISYsNivE0zUOJQ7KYSL7JcRzk8kSm9Zh/eWQR2bgjZaGs2mO+8UzO67L4DzK0CpR9Ekf/nkNKeYCspkg1lPq0gonx6ZcgYGBjkj/8dhhwpcgxbkZ0DQEgds="]},{"alg":"RS256","kty":"RSA","use":"sig","n":"9iDfevFYfFg1KiaPQrsMgzrUd_CXqGOetgCICYdJ5bhDFwKR3F-dvM0lyUZqMh1gzRXxp9SYRCn4eIZqOzHP5-3oAjyZLtmq3kcYHDamsyvOP8fCoqLmIRFa8fPCtBVUC2HL54FHHQCJic_aSHItnL8O1WvDn6Z598_mXkZk38esaJ7v_MpnMUk5EhbQrygWe0wLEbjmfNOnqVtDhoSh7WXl7CeeUjmCPPyISqczqkoPWUAAu5D0O4MQpxzaG3lybDtqaDeRO2vQeNMSjtvrheUvmnBArbozXYS4l0h6PsKJ_S-NZUjIVvaUR-U7kbREbbN7YfcFUceWVsJnoQjfyQ","e":"AQAB","kid":"PD2XrYfU_sdLuZTPbHMKn","x5t":"ugzQE7Uk10LZ-q4urzJEi3o-DDw","x5c":["MIIDATCCAemgAwIBAgIJZV/UKPmJr79uMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMTE2ZzbmQtam9lbC5hdXRoMC5jb20wHhcNMjAwNTA0MjEyNTAwWhcNMzQwMTExMjEyNTAwWjAeMRwwGgYDVQQDExNmc25kLWpvZWwuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9iDfevFYfFg1KiaPQrsMgzrUd/CXqGOetgCICYdJ5bhDFwKR3F+dvM0lyUZqMh1gzRXxp9SYRCn4eIZqOzHP5+3oAjyZLtmq3kcYHDamsyvOP8fCoqLmIRFa8fPCtBVUC2HL54FHHQCJic/aSHItnL8O1WvDn6Z598/mXkZk38esaJ7v/MpnMUk5EhbQrygWe0wLEbjmfNOnqVtDhoSh7WXl7CeeUjmCPPyISqczqkoPWUAAu5D0O4MQpxzaG3lybDtqaDeRO2vQeNMSjtvrheUvmnBArbozXYS4l0h6PsKJ/S+NZUjIVvaUR+U7kbREbbN7YfcFUceWVsJnoQjfyQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSvFFz/6dgaDMtcs0GP13J6OuFFmjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAC/BD3IOVR4lf31yLyE7I2sIiZOG1ttze/5iwtnUElfeMhR9T2OXGFov+Q2AHDs2uWLuLitK3dfXx0Bz1TTJ21XPCuQuWa2msiMsksjZB+R/R1YgQzXmEfgKBp3oxEZhcEmtLcE4t6GyGAJtHu2/UgRHbwHiX2Nsu3myrAqXqUVpw3f7EPCy/6OuXnFzM6vi5welTI8HyMFqgEnnjbi+Ht0n/xsQDwE6K9UOXy+QKjq1aFXhQ+J/xJQUDi1Wz5zp5/QLpJ8Tnr5eEWIAggH6TE8m+zWbvRcUC/OAatDe0asHMqgcm8VcMn97xZdRyrJWRL2qcnhdqmaw0FFIhGWMAks="]}]}
    for key in jwks['keys']:

        # print(f"key kid: {key['kid']}")   # Debugging why rsa_key not found

        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
            break   # No need to look further
    
    # Now finally verify the signature
    if rsa_key:
        try:
            # Straight from JWT documentation, https://python-jose.readthedocs.io/en/latest/jwt/api.html
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)


'''
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    
    if 'permissions' not in payload:
        raise AuthError({
                'code': 'invalid_token',
                'description': 'Unable to find permissions.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
                'code': 'forbidden',
                'description': 'User does not have required permissions.'
        }, 403)

    return True


'''
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method to validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method

    Call it with:  @requires_auth('get:drinks-detail')
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator