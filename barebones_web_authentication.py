import time, json, hmac, hashlib, secrets, string, base64, html, subprocess, datetime, http.client, http.cookies
from urllib.parse import urlparse, parse_qsl, urlencode, quote

# config for the authentication system (override as needed in views)s
CONFIG = {
    "SESSION_SECRET": None,     # 32-byte encoded string (e.g. generate using secrets.token_urlsafe(32))
    "SUPPORT_CONTACT": None,    # email address included in error messages
    "LOGIN_TYPES": [
        "GOOGLE_SSO",   # enable Google Single Sign-On (SSO) (requires GOOGLE_SSO config)
        "EMAIL_OTP",    # enable emailing a One-Time Passcode to the user (requires EMAIL_OTP config)
        "PASSWORD",     # enable preset passwords for users (requires USERS['<username>']['PASSWORD'] config)
    ],
    "EMAIL_OTP": {
        "ENCRYPTION_KEY": None,     # 32-bytes in hex (e.g. generate using secrets.token_hex(32))
        "EMAIL_BACKEND": "AWS_SES", # only AWS SES is supported, currently
        "AWS_REGION": None,         # the AWS region for the SES API (e.g. "us-west-2")
        "AWS_KEY_ID": None,         # your AWS Key ID that has the "ses:SendEmail" permission in IAM
        "AWS_SECRET": None,         # the secret for your AWS Key ID
        "AWS_FROM_EMAIL": None,     # what email the OTP emails have as their From: address (e.g. '"Server, Auth" <auth@example.com>')
    },
    "GOOGLE_SSO": {
        "CLIENT_ID": None,          # client_id for your Google OAuth application
        "CLIENT_SECRET": None,      # client_secret that compliments your client_id
        "REDIRECT_URI": None,       # the redirect_uri that needs to be used for OAuth
    },
    "USERS": {
        #"<username>": {
        #    "ROLES": ["<role_name", ...],
        #    "EMAIL": "<email>",
        #    # include if user has a password set (use password_generate_hash(b"mypassword") to generate the PASSWORD dict)
        #    "PASSWORD": {
        #        "algs": [{"type": "scrypt", "salt": "<base64 16-bytes>", "n": 2**14, "r": 8, "p": 5, "maxmem": 0, "dklen": 64}],
        #        "final_hash": "<base64 64-bytes>",
        #    },
        #    # include if user has 2FA via TOTP (use totp_generate_secret() to generate a new TOTP secret)
        #    "TOTP": {"secret": "<base32 20-bytes>", "issuer": "<site_name>", "label": "<username>"},
        #},
        #...
    },
}

###########
## Utils ##
###########

# password utils
def password_generate_hash(initial_password_bytes, algs=None):
    """ Hash a provided password and return the encoded dict of algorithms used and final hash. """
    if algs is None:
        salt = base64.b64encode(secrets.token_bytes(16)).decode()
        algs = [{"type": "scrypt", "salt": salt, "n": 2**14, "r": 8, "p": 5, "maxmem": 0, "dklen": 64}]
    cur_hash = initial_password_bytes
    for alg_ref in algs:
        if alg_ref['type'] == "scrypt":
            cur_hash = hashlib.scrypt(
                cur_hash,
                salt=base64.b64decode(alg_ref['salt']),
                n=alg_ref['n'],
                r=alg_ref['r'],
                p=alg_ref['p'],
                maxmem=alg_ref['maxmem'],
                dklen=alg_ref['dklen'],
            )
        else:
            raise NotImplementedError(f"unknown algorithm {alg_ref['type']}")
    return {"algs": algs, "final_hash": base64.b64encode(cur_hash).decode()}

def password_check(password_ref, submitted_password):
    """ Validate a user's password against the one stored in the configuration. """
    cur_hash = submitted_password.encode()
    for alg_ref in password_ref['algs']:
        if alg_ref['type'] == "scrypt":
            cur_hash = hashlib.scrypt(
                cur_hash,
                salt=base64.b64decode(alg_ref['salt']),
                n=alg_ref['n'],
                r=alg_ref['r'],
                p=alg_ref['p'],
                maxmem=alg_ref['maxmem'],
                dklen=alg_ref['dklen'],
            )
        else:
            raise NotImplementedError(f"unknown algorithm {alg_ref['type']}")
    return secrets.compare_digest(cur_hash, base64.b64decode(password_ref['final_hash']))


# TOTP utils
def totp_generate_secret():
    """ Generate a new TOTP secret (160 bits entropy)  """
    return base64.b32encode(secrets.token_bytes(20)).decode().replace("=", "")

def totp_encode_uri(totp_ref):
    """ Make QR-code TOTP URI (e.g. otpauth://totp/user123?secret=A3C...&issuer=Site123)"""
    args = {"secret": totp_ref['secret'], "issuer": totp_ref['issuer']}
    return f"otpauth://totp/{quote(totp_ref['label'], safe='')}?{urlencode(args)}"

def totp_calc(secret_b32, c):
    """ Calculate valid HOTP code from secret and counter """
    secret_b32 += "=" * (8 - (len(secret_b32) % 8))
    secret_bytes = base64.b32decode(secret_b32, casefold=True)
    c_digest = hmac.digest(secret_bytes, c.to_bytes(8, byteorder="big"), hashlib.sha1)
    offset = c_digest[-1] & 0xF
    code = str((
        (c_digest[offset] & 0x7F) << 24
        | c_digest[offset + 1] << 16
        | c_digest[offset + 2] << 8
        | c_digest[offset + 3]
    ) % 10**6).zfill(6)
    return code

def totp_check(secret_b32, submitted_code, t=None):
    """ Validate a user's TOTP against the one stored in the configuration. """
    t = int(time.time()) if t is None else t
    c_t = int(t / 30)
    valid_codes = [totp_calc(secret_b32, c_t), totp_calc(secret_b32, c_t - 1), totp_calc(secret_b32, c_t + 1)]
    for valid_code in valid_codes:
        if secrets.compare_digest(submitted_code.encode(), valid_code.encode()):
            return True
    return False


# cookie-based session signatures utils
def sign_dict(input_dict):
    """ Convert a dictionary to a signed string. """
    encoded = base64.urlsafe_b64encode(json.dumps(input_dict).encode()).decode().replace("=", "")
    timestamp = int(time.time())
    digest = hmac.new(CONFIG['SESSION_SECRET'].encode(), digestmod=hashlib.sha256)
    digest.update(encoded.encode())
    digest.update(str(timestamp).encode())
    signed = f"{encoded}_{timestamp}_{digest.hexdigest()}"
    return signed

def verify_signed(signed):
    """ Convert a signed string to a dictionary. """
    result_dict = {}
    try:
        encoded, timestamp, digest = signed.rsplit("_", 2)
    except ValueError:
        encoded, timestamp, digest = ["", "0", ""]
    verify = hmac.new(CONFIG['SESSION_SECRET'].encode(), digestmod=hashlib.sha256)
    verify.update(encoded.encode())
    verify.update(timestamp.encode())
    verify_digest = verify.hexdigest()
    verify_match = hmac.compare_digest(digest, verify_digest)
    if verify_match:
        result_dict = json.loads(base64.urlsafe_b64decode(encoded.encode() + b"=="))
    return verify_match, result_dict, int(timestamp)


# email/sms OTP encryption utils
def encrypt(data_dict, enc_key):
    iv_hex = secrets.token_hex(16)
    process = subprocess.Popen(
        ["openssl", "aes-256-cbc", "-K", enc_key, "-iv", iv_hex, "-in", "/dev/stdin", "-out", "/dev/stdout"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    enc, err = process.communicate(json.dumps(data_dict).encode())
    enc_64 = base64.urlsafe_b64encode(enc).decode().replace("=", "")
    enc_result = f"{iv_hex}_{enc_64}"
    return enc_result

def decrypt(encrypted_str, enc_key):
    if not encrypted_str:
        return None
    iv_hex, enc_64 = encrypted_str.split("_", 1)
    enc_bytes = base64.urlsafe_b64decode(enc_64 + "==")
    process = subprocess.Popen(
        ["openssl", "aes-256-cbc", "-d", "-K", enc_key, "-iv", iv_hex, "-in", "/dev/stdin", "-out", "/dev/stdout"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    dec_bytes, err = process.communicate(enc_bytes)
    dec_dict = json.loads(dec_bytes)
    return dec_dict

# email sending util (copied from https://github.com/diafygi/barebones-ses-sending)
def send_ses_email(msg=None, api_payload=None, aws_region=None, aws_key_id=None, aws_secret=None):
    # email sending contents
    addr_list = lambda addr_str: [formataddr((rname, remail)) for rname, remail in getaddresses(addr_str) if remail]
    PAYLOAD = json.dumps(api_payload or {
        "FromEmailAddress": msg['from'],
        "Destination": {
            "ToAddresses": addr_list(msg.get("to", "")),
            "CcAddresses": addr_list(msg.get("cc", "")),
            "BccAddresses": addr_list(msg.get("bcc", "")),
        },
        "ReplyToAddresses": addr_list(msg.get("reply-to", "")),
        "Content": { "Raw": { "Data": base64.b64encode(bytes(msg)).decode() } },
    }).encode()
    NOW = datetime.datetime.utcnow()
    REF = {
        "aws_key_id": aws_key_id,
        "aws_secret": aws_secret,
        "algo": "AWS4-HMAC-SHA256",
        "req_type": "aws4_request",
        "host": "email." + aws_region + ".amazonaws.com",
        "region": aws_region,
        "service": "ses",
        "method": "POST",
        "path": "/v2/email/outbound-emails",
        "query": "",
        "header_names": "content-type;host;x-amz-date",
        "content_type": "application/json",
        "date": NOW.strftime('%Y%m%d'),
        "timestamp": NOW.strftime('%Y%m%dT%H%M%SZ'),
        "payload_hash": hashlib.sha256(PAYLOAD).hexdigest(),
        "request_hash": None,
        "signature": None,
    }
    # Create the canonical request
    canonical_request = (
        "{method}\n"
        "{path}\n"
        "{query}\n"
        "content-type:{content_type}\n"
        "host:{host}\n"
        "x-amz-date:{timestamp}\n"
        "\n"
        "{header_names}\n"
        "{payload_hash}"
    ).format(**REF).encode()
    REF['request_hash'] = hashlib.sha256(canonical_request).hexdigest()
    # Create the signature
    sig_payload = (
        "{algo}\n"
        "{timestamp}\n"
        "{date}/{region}/{service}/{req_type}\n"
        "{request_hash}"
    ).format(**REF).encode()
    kSecret = "AWS4{aws_secret}".format(**REF).encode()
    kDate = hmac.new(kSecret, REF['date'].encode(), hashlib.sha256).digest()
    kRegion = hmac.new(kDate, REF['region'].encode(), hashlib.sha256).digest()
    kService = hmac.new(kRegion, REF['service'].encode(), hashlib.sha256).digest()
    kReqType = hmac.new(kService, REF['req_type'].encode(), hashlib.sha256).digest()
    REF['signature'] = hmac.new(kReqType, sig_payload, hashlib.sha256).hexdigest()
    # Create the authorization header
    authorization_header = (
        "{algo} "
        "Credential={aws_key_id}/{date}/{region}/{service}/{req_type}, "
        "SignedHeaders={header_names}, "
        "Signature={signature}"
    ).format(**REF)
    # Make the request
    conn = http.client.HTTPSConnection(REF['host'])
    conn.request(REF['method'], REF['path'], PAYLOAD, {
        "Host": REF['host'],
        "Content-Type": REF['content_type'],
        "X-Amz-Date": REF['timestamp'],
        "Authorization": authorization_header,
    })
    resp = conn.getresponse()
    return resp


################
## Decorators ##
################

def load_session(view_func):
    """ Decorator to load the signed session from the user's cookie. """ 
    def wrapper(environ, start_response):
        # default to a blank session for each request
        environ['app.cookie_session'] = {}
        # try to load and verify the user's session from their cookies
        cookies = http.cookies.SimpleCookie(environ.get("HTTP_COOKIE") or "")
        if cookies.get("session"):
            verify_match, session_dict, timestamp = verify_signed(cookies['session'].value)
            # successfully verified the session, so set it as the session in the environ
            if verify_match:
                environ['app.cookie_session'] = session_dict
        # proceed to process the view as normal
        result = view_func(environ, start_response)
        return result
    return wrapper


def login_required(roles_required=None, redirect_to_login=True):
    """ Decorator to require a valid user id in their session and optional role requirement. """
    def decorator(view_func):
        # load the user's session, if any
        @load_session
        def wrapper(environ, start_response):
            # check for presence of user it in their session
            is_authenticated = bool(environ.get('app.cookie_session', {}).get("user"))
            # also check if they user has the required roles
            if is_authenticated and roles_required is not None:
                roles = CONFIG['USERS'].get(environ['app.cookie_session']['user'], {}).get("ROLES", [])
                if not list(set(roles_required) & set(roles)):
                    is_authenticated = False
            # user isn't authenticated
            if not is_authenticated:
                # redirect them to login and indicate where they should go after logging in
                if redirect_to_login:
                    next_params = urlencode([
                        ("next", "{}{}{}".format(
                            environ['PATH_INFO'],
                            "?" if environ.get("QUERY_STRING") else "",
                            environ.get("QUERY_STRING") or "",
                        ))
                    ])
                    start_response("302 Found", [("Location", f"/login?{next_params}")])
                    return []
                # otherwise just return an error
                else:
                    start_response('404 Not Found', [('Content-type', 'text/plain')])
                    return [b"404 Not Found"]
            # user is authenticated, so continue processing as normal
            result = view_func(environ, start_response)
            return result
        return wrapper
    return decorator

###########
## Views ##
###########

@load_session
def login(environ, start_response):
    """ Login for the Vote411 custom admin interface. """
    # get current session dict
    session = environ['app.cookie_session']

    # default empty errors
    email_errors = ""
    login_errors = ""

    ##########
    ## POST ##
    ##########
    if environ.get("REQUEST_METHOD") == "POST":

        # convert POST body into dict
        post_raw = environ.get("wsgi.input").read(int(environ.get("CONTENT_LENGTH")))
        post_body = dict(parse_qsl(post_raw.decode()))

        ##########################
        ## login via email link ##
        ##########################
        if post_body['login_type'] == "email_otp":

            # require the user to be pre-registered
            if CONFIG['USERS'].get(post_body.get("username"), {}).get("EMAIL"):

                # generate and send OTP code
                user_email = CONFIG['USERS'][post_body['username']]['EMAIL']
                otp_code = "".join([secrets.choice(string.digits) for i in range(6)])
                send_ses_email(
                    api_payload={
                        "FromEmailAddress": CONFIG['EMAIL_OTP']['AWS_FROM_EMAIL'],
                        "Destination": { "ToAddresses": [user_email] },
                        "Content": {
                            "Simple": {
                                "Subject": { "Data": "Login code" },
                                "Body": { "Text": { "Data": f"{otp_code} is your login code." } },
                            },
                        },
                    },
                    aws_region=CONFIG['EMAIL_OTP']['AWS_REGION'],
                    aws_key_id=CONFIG['EMAIL_OTP']['AWS_KEY_ID'],
                    aws_secret=CONFIG['EMAIL_OTP']['AWS_SECRET'],
                )

                # build OTP payload
                otp_id = f"{secrets.token_urlsafe(16)}"
                session["otp_" + otp_id] = encrypt({
                    "code": otp_code,
                    "user": post_body['username'],
                    "query": environ.get("QUERY_STRING") or "",
                    "path": environ.get("PATH_INFO") or "",
                }, CONFIG['EMAIL_OTP']['ENCRYPTION_KEY'])

                # redirect user to their next url
                start_response('302 Found', [
                    ('Location', f"/login/code/{otp_id}"),
                    ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
                ])
                return []

            # default is that the email sending failed
            email_errors = "Either this user doesn't exist or their email hasn't been configured."

        ##########################
        ## login via google sso ##
        ##########################
        elif post_body['login_type'] == "google_sso":

            # build SSO url
            sso_state = f"google_{secrets.token_urlsafe(16)}"
            google_sso_url = "{}?{}".format(
                "https://accounts.google.com/o/oauth2/v2/auth",
                urlencode([
                    ("client_id", CONFIG['GOOGLE_SSO']['CLIENT_ID']),
                    ("redirect_uri", CONFIG['GOOGLE_SSO']['REDIRECT_URI']),
                    ("response_type", "code"),
                    ("scope", "email"),
                    ("state", sso_state),
                ]),
            )

            # keep track of SSO state in user's session cookie
            query_dict = dict(parse_qsl(environ.get("QUERY_STRING") or ""))
            session["sso_" + sso_state] = json.dumps({"next": query_dict.get("next")})

            # redirect user to their next url
            start_response('302 Found', [
                ('Location', google_sso_url),
                ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
            ])
            return []

        ########################
        ## login via password ##
        ########################
        elif post_body['login_type'] == "password":

            # make sure the user has set a password
            if CONFIG['USERS'].get(post_body.get("username", ""), {}).get("PASSWORD"):

                # check their saved password against the submitted one
                if password_check(CONFIG['USERS'][post_body['username']]['PASSWORD'], post_body.get("password", "")):

                    # valid password, so log the user in
                    session['user'] = post_body['username']

                    # determine the next url
                    next_url = dict(parse_qsl(environ.get("QUERY_STRING") or "")).get("next") or "/"
                    if not next_url.startswith("/"):
                        next_url = "/"  # only allow relative locations for logins

                    # redirect the user on to their logged-in location
                    start_response('302 Found', [
                        ('Location', next_url),
                        ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
                    ])
                    return []

            # default is that the password login failed
            login_errors = "Either this user doesn't exist or the password was invalid."

    ##########################
    ## GET and failed POSTs ##
    ##########################

    # render template
    login_type_templates = {
        "EMAIL_OTP": """
            <form method="post">
                <input type="hidden" name="login_type" value="email_otp">
                <label for="username">Username:</label>
                <input id="username" name="username" placeholder="(e.g. info@example.com)">
                <input type="submit" value="Send verification code">
                <div style="color:red;">EMAIL_ERRORS_HERE</div>
            </form>
        """,
        "GOOGLE_SSO": """
            <form id="google_sso_form" method="post">
                <input type="hidden" name="login_type" value="google_sso">
                <input type="submit" value="Login via Google Account">
            </form>
            <script>
                document.querySelector("#google_sso_form").addEventListener("submit", (e) => {
                    document.querySelector("#google_sso_form input[type=submit]").value = "Redirecting..."
                });
            </script>
        """,
        "PASSWORD": """
            <form method="post">
                <input type="hidden" name="login_type" value="password">
                <label for="username">Username:</label>
                <input id="username" type="text" name="username" placeholder="(e.g. info@example.com)">
                <label for="password">Password:</label>
                <input id="password" type="password" name="password" placeholder="(e.g. ********)">
                <input type="submit" value="Login">
                <div style="color:red;">LOGIN_ERRORS_HERE</div>
            </form>
        """,
    }
    login_types_combined = "<p>or</p>".join([login_type_templates[lt] for lt in CONFIG['LOGIN_TYPES']])
    data = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Login</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                <h1>
                    Login Required
                </h1>
                LOGIN_TYPES_HERE
            </body>
        </html>
    """.replace(
        "LOGIN_TYPES_HERE", login_types_combined,
    ).replace(
        "EMAIL_ERRORS_HERE", html.escape(email_errors),
    ).replace(
        "LOGIN_ERRORS_HERE", html.escape(login_errors),
    ).encode()

    # return error response
    start_response('200 OK', [
        ('Content-type', 'text/html'),
        ('Content-length', str(len(data))),
    ])
    return [data]


@load_session
def login_sso_redirect(environ, start_response):
    """ SSO redirect_uri interface. """

    # parse the SSO redirect params
    query = dict(parse_qsl(environ.get("QUERY_STRING") or ""))
    redirect_state = query.get("state") or ""
    redirect_code = query.get("code") or ""
    redirect_error = query.get("error") or ""

    # reload the page if no cookies are set, since cookies aren't initially passed when redirecting back because of SameSite=Strict setting
    session = environ['app.cookie_session']
    if not session:
        data = b'''
            <!DOCTYPE html>
            <html>
                <head>
                    <meta charset="utf-8">
                    <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                    <meta name="robots" content="noindex">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <meta http-equiv="refresh" content="0">
                    <style>
                        @media (prefers-color-scheme: dark) {
                            html, input { background-color:#222; color:#eee; }
                            a { color:#aaf; }
                        }
                    </style>
                </head>
                <body>
                    Redirecting...
                </body>
            </html>
        '''
        start_response('200 OK', [
            ('Content-type', 'text/html'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # verify that the redirect has a valid state
    state_data = session.pop("sso_" + redirect_state, None)
    if state_data is None:
        data = b"Invalid redirect state. Please go back and try logging in again."
        start_response('400 Bad Request', [
            ('Content-type', 'text/plain'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # show any SSO errors
    if not redirect_code:
        data = (
            f"Error: {redirect_error or 'unknown_error'}. "
            f"Please go back and try again. "
            f"If you keep seeing this, please email {CONFIG['SUPPORT_CONTACT']}."
        ).encode()
        start_response('400 Bad Request', [
            ('Content-type', 'text/plain'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # get access token from code
    token_payload = urlencode([
        ("client_id", CONFIG['GOOGLE_SSO']['CLIENT_ID']),
        ("client_secret", CONFIG['GOOGLE_SSO']['CLIENT_SECRET']),
        ("redirect_uri", CONFIG['GOOGLE_SSO']['REDIRECT_URI']),
        ("code", redirect_code),
        ("grant_type", "authorization_code"),
    ]).encode()
    token_conn = http.client.HTTPSConnection("oauth2.googleapis.com")
    token_conn.request("POST", "/token", token_payload, {
        "Content-length": str(len(token_payload)),
        "Content-type": "application/x-www-form-urlencoded",
    })
    token_resp = token_conn.getresponse()
    token_dict = json.loads(token_resp.read())
    access_token = token_dict['access_token']

    # get userinfo url
    meta_conn = http.client.HTTPSConnection("accounts.google.com")
    meta_conn.request("GET", "/.well-known/openid-configuration", None, {})
    meta_resp = meta_conn.getresponse()
    meta_dict = json.loads(meta_resp.read())
    userinfo_endpoint = urlparse(meta_dict['userinfo_endpoint'])

    # get user's email
    userinfo_conn = http.client.HTTPSConnection(userinfo_endpoint.netloc)
    userinfo_conn.request("GET", userinfo_endpoint.path, None, {
        "Authorization": f"Bearer {access_token}",
    })
    userinfo_resp = userinfo_conn.getresponse()
    userinfo_dict = json.loads(userinfo_resp.read())

    # reject if not a valid email
    if not userinfo_dict['email_verified']:
        data = (
            f"Error: unverified_email. Please go back and try again. "
            f"If you keep seeing this, please email {CONFIG['SUPPORT_CONTACT']}."
        ).encode()
        start_response('400 Bad Request', [
            ('Content-type', 'text/plain'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # reject if we can't find this email in the user list
    users = [k for k, v in CONFIG['USERS'].items() if v['EMAIL'] == userinfo_dict['email']]
    if len(users) != 1:
        data = b"Error: Your Google account doesn't match any user email."
        start_response('400 Bad Request', [
            ('Content-type', 'text/plain'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # set user's email as their logged in session
    session = environ['app.cookie_session']
    session['user'] = users[0]

    # figure out where a user should go after they authenticate
    state_dict = json.loads(state_data)
    next_url = state_dict.get("next") or "/"
    if not next_url.startswith("/"):
        next_url = "/"  # only allow relative locations for logins

    # redirect the user on to their logged-in location
    start_response('302 Found', [
        ('Location', next_url),
        ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ])
    return []


@load_session
def login_otp(environ, start_response):
    """ Login via OTP code sent to user's email. """

    # look up the user's current encrypted otp session
    session = environ['app.cookie_session']
    otp_id = environ['PATH_INFO'].rsplit("/", 1)[1]
    encrypted_str = session.get("otp_" + otp_id)
    otp_dict = decrypt(encrypted_str, CONFIG['EMAIL_OTP']['ENCRYPTION_KEY'])

    # invalid otp session
    if not otp_dict:
        data = b"Invalid session. Please go back and try logging in again."
        start_response('400 Bad Request', [
            ('Content-type', 'text/plain'),
            ('Content-length', str(len(data))),
        ])
        return [data]

    # default empty errors
    code_errors = ""

    ##########
    ## POST ##
    ##########
    if environ.get("REQUEST_METHOD") == "POST":

        # convert POST body into dict
        post_raw = environ.get("wsgi.input").read(int(environ.get("CONTENT_LENGTH")))
        post_body = dict(parse_qsl(post_raw.decode()))

        # validate the entered code
        code_match = hmac.compare_digest((post_body.get("code") or "").strip(), otp_dict['code'])
        if code_match:

            # set the user's authenticated session and clear the current OTP payload
            session['user'] = otp_dict['user']
            session.pop("otp_" + otp_id, None)

            # figure out where a user should go after they authenticate
            query = dict(parse_qsl(otp_dict['query']))
            next_url = query.get("next") or "/"
            if not next_url.startswith("/"):
                next_url = "/"  # only allow relative locations for logins

            # redirect the user on to their logged-in location
            start_response('302 Found', [
                ('Location', next_url),
                ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
            ])
            return []

        # not matching to clear the code and force the user to try again
        session.pop("otp_" + otp_id, None)
        code_errors = "Invalid code. Please go back and request another code."

    ##########################
    ## GET and failed POSTs ##
    ##########################

    # update the back link
    prev_url = "{}{}{}".format(
        otp_dict['path'],
        "?" if otp_dict['query'] else "",
        otp_dict['query'],
    )

    # default template
    data = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Login Validation</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                <p>
                    We sent you an email with a 6-digit code. Please enter it below.
                </p>
                <form method="post">
                    <label for="code">Code:</label>
                    <input id="code" type="text" name="code" placeholder="(e.g. 123456)" autofocus>
                    <input type="submit" value="Submit code">
                    <div style="color:red;">CODE_ERRORS_HERE</div>
                </form>
                <small style="display:block; margin-top:1em;">
                    <a href="PREV_URL_HERE">‹ go back</a>
                </small>
            </body>
        </html>
    """.replace(
        "CODE_ERRORS_HERE", html.escape(code_errors),
    ).replace(
        "PREV_URL_HERE", html.escape(prev_url),
    ).encode()

    # return error response
    start_response('200 OK', [
        ('Content-type', 'text/html'),
        ('Content-length', str(len(data))),
    ])
    return [data]


@load_session
def logout(environ, start_response):
    """ Logout interface. """
    # remove the user's id and any sso states from the session
    session = environ['app.cookie_session']
    for session_key in list(session.keys()):
        if (
            session_key == "user"
            or session_key.startswith("sso_")
            or session_key.startswith("otp_")
        ):
            session.pop(session_key, None)

    # respond with updated session
    data = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Logout</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                You are now logged out. <a href="LOGIN_URL_HERE">Click here</a> to login again.
            </body>
        </html>
    """.replace(
        "LOGIN_URL_HERE", "/login",
    ).encode()

    start_response('200 OK', [
        ('Content-type', 'text/html'),
        ('Content-length', str(len(data))),
        ('Set-Cookie', f"session={sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ])
    return [data]


# URLs for these views
URLS = [
    (r"^/login$", login),
    (r"^/login/redirect$", login_sso_redirect),
    (r"^/login/code/[^/]+$", login_otp),
    (r"^/logout$", logout),
]

