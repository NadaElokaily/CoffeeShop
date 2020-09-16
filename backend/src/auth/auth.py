import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


# AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
# ALGORITHMS = ['RS256']
# API_AUDIENCE = 'dev'
AUTH0_DOMAIN = 'coffeeshopxx.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'http://127.0.0.1:5000/drinks'

'''  
https://coffeeshopxx.us.auth0.com/authorize?
audience=http://127.0.0.1:5000/drinks&
response_type=token&
client_id=6C18A37VXjizUW1qOjRpnvATsnK8tU51&
redirect_uri=http://127.0.0.1:5000/
'''

''' manager
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im81MDBFNmh0WHFFZlhIVWJxNl9JZSJ9.eyJpc3MiOiJodHRwczovL2NvZmZlZXNob3B4eC51cy5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWY1YWIzYTFjYjdkZTcwMDY5NzgyYWJmIiwiYXVkIjoiaHR0cDovLzEyNy4wLjAuMTo1MDAwL2RyaW5rcyIsImlhdCI6MTYwMDI4MzI5NCwiZXhwIjoxNjAwMjkwNDk0LCJhenAiOiI2QzE4QTM3VlhqaXpVVzFxT2pScG52QVRzbks4dFU1MSIsInNjb3BlIjoiIiwicGVybWlzc2lvbnMiOlsiZGVsZXRlOmRyaW5rcyIsImdldDpkcmlua3MtZGV0YWlsIiwicGF0Y2g6ZHJpbmtzIiwicG9zdDpkcmlua3MiXX0.v657VS-7n46aR5oWZsHhokvC2avu7MT4YiiAqzzJAZshktAB4n9iDQp-8t-J_39vysDDtyVgtqvtveFKQzTE9L_5gdWqYxa4uS_Df88hG_9tpHeaLcVenwnK022Hsyvajd9egHSqO7orGQcZHqEcXAUsD857qi4XwltTqeQsf3r6ZSmNFdCxT9vB93pANCnlRpjIDv8sc0n16xW7FzE7-Tnmoi0Psa8GzgnsrCHKcYPb-xQZuUKFtltPXDEHDiqUZVOYddAHOxIxnnc1HjiJSmdViVpUXDJMpT3PQY0HjVkL131-4CB7m4ezEiXPL6LsawosaPtpN4l6vNJBuYomeQ
'''
''' barista
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im81MDBFNmh0WHFFZlhIVWJxNl9JZSJ9.eyJpc3MiOiJodHRwczovL2NvZmZlZXNob3B4eC51cy5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NWY2MjAyNDExNWFiM2EwMDc3MmQ4ODE3IiwiYXVkIjoiaHR0cDovLzEyNy4wLjAuMTo1MDAwL2RyaW5rcyIsImlhdCI6MTYwMDI4MzM0NywiZXhwIjoxNjAwMjkwNTQ3LCJhenAiOiI2QzE4QTM3VlhqaXpVVzFxT2pScG52QVRzbks4dFU1MSIsInNjb3BlIjoiIiwicGVybWlzc2lvbnMiOlsiZ2V0OmRyaW5rcy1kZXRhaWwiXX0.i6rctR-9mVF9nD3_KPupRWgMU1rEn0XIvVeVvZnip_qxue2dGZJBSqH9zuv-XO-X1hXDKPQyTwaKDMV7IKPlWiRHw8eSM1o7dtAdot19ZZYbtoeFsqaimtMaG4Z99CqVL9R2kc0TXjHtW0aURAy3Lnu4-2rShyF-ahT54o9qFaF3YZM_TZ_XzvdPOh_vasnqCkCwb1S9xU8A3Uktju8IjIf_BJ4PY7MVbybpH8qUz06aJgL9KLryzksRJR5S9QRT0-923Qb6Tra4KxfQZe2XI7iPAc2sBn5XEkBxs2Y5oIdYiOZDIlEdhws1BXzjKDeGi77Vk78N0Ht7RXwEPGxnuA
'''
'''udacity manager
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik4wTkNOVEEzTWpaQ1FUa3lRMEl6TmtORk0wWXhRVFUwT1RFMFFVVkNSRUpDT1RBME1EUXpOUSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDY3MTQ4MTQ0MTcwNjk3MTI4OTMiLCJhdWQiOlsiZGV2IiwiaHR0cHM6Ly91ZGFjaXR5LWZzbmQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTU2MDg4OTU5NiwiZXhwIjoxNTYwODk2Nzk2LCJhenAiOiJPSjVwQk9ZSURFa09FVFVmUWo1ajdsSDZFTFcwMkd1MCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJkZWxldGU6ZHJpbmtzIiwiZ2V0OmRyaW5rcyIsImdldDpkcmlua3MtZGV0YWlsIiwicGF0Y2g6ZHJpbmtzIiwicG9zdDpkcmlua3MiXX0.Qk-5FC2X_RUkK00WKARYCKw_877XFuaT5ND3f3ObD9Ly1e1GMfJXhi3McV12binGGCw6x241erIjGB0t8WbWdU3bYpIVD1klZ64DVLQ8Q2LQ2NzB3eFEOgGLL85az1jIDbRiuATIRbbBOWILPJ6h6KR9L5hExklf2zuj3Bnwm7zMRmVpIJmjrUt4bWjtTOguOwJ0IVQsk4PDjGxzwfrUWFCFNDqN_u15JNLxeH21C-QvCpHs3D4Aodeh1qFUuWHfK_Gyfu91AitXPTVZRX9eZbUOVkGT3JMn4sKn9oGaKFTx2E-Y4DmoECG0uWImbX_wiRjx4aTeo7Q7hKSReMToPA
'''
'''udacity barista
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik4wTkNOVEEzTWpaQ1FUa3lRMEl6TmtORk0wWXhRVFUwT1RFMFFVVkNSRUpDT1RBME1EUXpOUSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDY3MTQ4MTQ0MTcwNjk3MTI4OTMiLCJhdWQiOlsiZGV2IiwiaHR0cHM6Ly91ZGFjaXR5LWZzbmQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTU2MDg5MDE2MCwiZXhwIjoxNTYwODk3MzYwLCJhenAiOiJPSjVwQk9ZSURFa09FVFVmUWo1ajdsSDZFTFcwMkd1MCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJwZXJtaXNzaW9ucyI6WyJnZXQ6ZHJpbmtzIiwiZ2V0OmRyaW5rcy1kZXRhaWwiXX0.j9ocW47_exQOkEa10ffh8eijGvrIMxnGRzCmbrXnfaN_8ULsgA7AnWYMtvP8RmPWvT9n8sReWnFuJajUHBUbnBO2GuJ4aM3-WDUBeJT0X_mpGUWs4lxaNTbIkWdiWPTsEiRnP3wT-dU_v3Olw2PB4UMajMIjSH-IdF2Y1CiJIOaM0gV44RGZRyRvj6C2_mOkMfoXxzw-HrVvTRCo1NcUPea5Bs04POni7azx-B7FstP_HLm0dEbbge4XbmovHwlIXknIoI8PbuGXeLBqE2hv8fErKFBuIykxzK0nErH5zSPCrkM-_9smb8TLGAH-E5j1KQb6SHDKtcV_QHnsUYFuXA
'''


## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@DONE implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
        "description":"Authorization header is expected"}, 401)
    parts = auth.split()
    if parts[0].lower() != "bearer":
        raise AuthError({"code":"authorization_header_malformed",
        "description":"Authorization header must start with Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)
    token = parts[1]
    return token

'''
@DONE implement check_permissions(permission, payload) method
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
                            'code': 'invalid_claims',
                            'description': 'Permissions not included in JWT.'
                        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True

'''
@DONE implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    # GET THE PUBLIC KEY FROM AUTH0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    
    # GET THE DATA IN THE HEADER
    unverified_header = jwt.get_unverified_header(token)
    
    # CHOOSE OUR KEY
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            # USE THE KEY TO VALIDATE THE JWT
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
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
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
