#
# Copyright (C) 2024 ColorTokens Inc.
# By Venky Raju <venky.raju@colortokens.com>
#
# This is a Null Oauth2 authorization server that can be used to 
# demonstrate single-sign-on for the Xshield portal without
# the need for a real IdP.

import os
import uuid
import json
import base64
import time
import jwt
import logging
import base64
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, request, redirect, session, jsonify
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Flask stuff
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Globals
xs_client_id = 'xshield'
idp_domain = None                   # Read from env (IDP_DOMAIN)
xs_domain = None                    # Read from env (XS_DOMAIN)
xs_client_secret = None             # Read from env (XS_CLIENT_SECRET)
codes = {}                          # Map codes to email addresses
keystore_path = 'keystore.json'     # Key storage

# Utility functions
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption())

    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)

    keystore = {
        'private_key': pem.decode('utf-8'),
        'public_key': pub_pem.decode('utf-8')
    }
    with open(keystore_path, 'w') as file:
        json.dump(keystore, file)

def load_private_key():
    with open(keystore_path, 'r') as file:
        keystore = json.load(file)
        return serialization.load_pem_private_key(
            keystore['private_key'].encode('utf-8'),
            password=None,
        )

def verify(auth_header):
    if not auth_header.startswith('Basic '):
        return False
    
    try:
        b64_value = auth_header.lstrip('Basic ')
        value = base64.b64decode(b64_value).decode('utf-8')
        id, secret = value.split(':')
        return (id == xs_client_id and secret == xs_client_secret)
    except:
        return False
    
# URL handlers

@app.route('/.well-known/openid-configuration')
def discovery():
    return jsonify({
        "issuer": "",
        "authorization_endpoint": f'${idp_domain}/authorize',
        "token_endpoint": f'${idp_domain}/token',
        "jwks_uri": f'${idp_domain}/jwks',
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        "claims_supported": ["sub", "aud", "exp", "iat"]
    })

def get_jwks():
    with open(keystore_path, 'r') as file:
        keystore = json.load(file)
    public_key = serialization.load_pem_public_key(keystore['public_key'].encode('utf-8'))
    public_numbers = public_key.public_numbers()
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "n": n, "e": e, "kid": "1"}]}

# Verify Client ID and Redirect URI
# No user authentication is performed - we're a Null i.e. Fake IdP, remember!
@app.route('/authorize')
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    email = request.args.get('login_hint')

    xs_redirect_uri = f'{xs_domain}/api/auth/callback-oauth'
    
    if client_id == xs_client_id and redirect_uri == xs_redirect_uri:
        code = uuid.uuid4().hex
        codes[code] = email
        redirect_url = f"{redirect_uri}?code={code}"
        if state:
            redirect_url += f"&state={state}"
        app.logger.info(f'Approved auth request for {email}')
        return redirect(redirect_url)
    
    app.logger.info(f'Rejected auth request for {email}')
    return "Invalid client details", 400

# Verify the HTTP Authorization header.
# 
@app.route('/token', methods=['POST'])
def token():

    if not 'Authorization' in request.headers:
        app.logger.info(f'Rejected token request: missing Auth header')
        return jsonify({"error": "Missing a necessary header"}), 400
    
    auth_header_value = request.headers.get('Authorization')
    if not verify(auth_header_value):
        app.logger.info(f'Rejected token request: client auth failure')
        return jsonify({"error": "Client authentication failure"}), 401
    
    authorization_code = request.form.get('code')
    email = codes[authorization_code]
    
    if not authorization_code or not email: 
        app.logger.info(f'Rejected token request: missing auth_code or email')
        return jsonify({"error": "Bad request"}), 400

    # Prepare the JWT payload
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=1),  # Expiration time
        "iat": datetime.utcnow(),         # Issued at time
        "scope": "read write"             # Scopes or permissions granted
    }

    # Load the RSA private key
    private_key = load_private_key()

    # Generate JWT
    encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": "1"})

    app.logger.info(f'Sent token for {email}')
    return jsonify(access_token=encoded_jwt, token_type="Bearer")


@app.route('/logout')
def logout():
    return redirect(f'{xs_domain}/auth/login')

@app.route('/jwks')
def jwks():
    return jsonify(get_jwks())

if __name__ != '__main__':

    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

    load_dotenv()
    idp_domain = os.getenv('IDP_DOMAIN')
    xs_domain = os.getenv('XS_DOMAIN')
    xs_client_secret = os.getenv('XS_CLIENT_SECRET')

    if not idp_domain or not xs_domain or not xs_client_secret:
        raise ValueError('Please set env variables for IDP_DOMAIN, XS_DOMAIN, XS_CLIENT_SECRET')
    
    generate_keys()
    app.logger.info('And we have lift off!')

