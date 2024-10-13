import barebones_web_authentication

############
## Config ##
############

# patch in the config options, secrets, and users you want
barebones_web_authentication.CONFIG['SESSION_SECRET'] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
barebones_web_authentication.CONFIG['LOGIN_TYPES'] = ["PASSWORD"]
barebones_web_authentication.CONFIG['USERS'] = {
    "testuser1": {
        "ROLES": ["admin"],
        "EMAIL": "testuser1@example.com",
        "PASSWORD": {
            # password = "foobar"
            "algs": [{"type": "scrypt", "salt": "qjqH5ZvDH8pH8r4tFj0J8Q==", "n": 16384, "r": 8, "p": 5, "maxmem": 0, "dklen": 64}],
            "final_hash": "4jqlD9GeCy/v/1RwV9r/Yx9IQzCAC+azVHCHiy0+SgvkkMnBxXqBBbTBVyHRSeLI+zJPsW5Z4K7vrUejkTMIqg==",
        },
    },
}

############################
## views for the wsgi app ##
############################

def homepage_view(environ, start_response):
    """
    This homepage is a public, unauthenticated page.
    """
    data = b"""
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Example App</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                <h1>Example App</h1>
                <p>This is an example of how barebones_web_authentication works with a wsgi application.</a>
                <ul>
                    <li>
                        <a href="/counter">A session cookie example</a> -
                        A public page that uses signed cookies for sessions
                    </li>
                    <li>
                        <a href="/admin">An authenticated example</a> -
                        A private page that requires a login
                        <ul>
                            <li>Test username: testuser1</li>
                            <li>Test password: foobar</li>
                        </ul>
                    </li>
                </ul>
            </body>
        </html>
    """
    start_response("200 OK", [("Content-Type", "text/html"), ("Content-Length", str(len(data)))])
    return [data]

@barebones_web_authentication.load_session
def counter_view(environ, start_response):
    """
    This counter page is public, and keeps track of how many time a button is clicked using
    a signed-cookie session.
    """
    # get the session from the environ (added by the decorator)
    session = environ['app.cookie_session']

    # increment click counter on POST requests
    session['num_clicks'] = session.get("num_clicks") or 0
    if environ.get("REQUEST_METHOD") == "POST":
        session['num_clicks'] += 1
        start_response('302 Found', [
            ('Location', "/counter"),
            ('Set-Cookie', f"session={barebones_web_authentication.sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
        ])
        return []

    # show number of clicks on GET requests
    data = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Counter Example</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                <h3>You have clicked the button COUNT_HERE times.</h3>
                <form method="post">
                    <input type="submit" value="Click Me">
                </form>
                <p>(to reset the counter, clear your cookies)</p>
                <p><a href="/">Go back to the list of examples</a></p>
            </body>
        </html>
    """.replace(
        "COUNT_HERE", str(session['num_clicks']),
    ).encode()
    start_response("200 OK", [
        ("Content-Type", "text/html"),
        ("Content-Length", str(len(data))),
        ('Set-Cookie', f"session={barebones_web_authentication.sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ])
    return [data]

@barebones_web_authentication.login_required(roles_required=['admin'])
def admin_view(environ, start_response):
    """
    This admin page is a private page that requires the user to login.
    """
    # get the user from the session in the environ (added by the decorator)
    session = environ['app.cookie_session']
    username = session['user']

    # display the logged-in user
    data = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <link rel="icon" href="data:;base64,iVBORw0KGgo="><!-- disable favicon request -->
                <meta name="robots" content="noindex">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Admin Example</title>
                <style>
                    @media (prefers-color-scheme: dark) {
                        html, input { background-color:#222; color:#eee; }
                        a { color:#aaf; }
                    }
                </style>
            </head>
            <body>
                <h1>Admin</h1>
                <p>You are now logged in as an admin (username=USERNAME_HERE).</p>
                <p><a href="/logout">Log out</a></p>
                <p><a href="/">Go back to the list of examples</a></p>
            </body>
        </html>
    """.replace(
        "USERNAME_HERE", str(session['user']),
    ).encode()
    start_response("200 OK", [
        ("Content-Type", "text/html"),
        ("Content-Length", str(len(data))),
        ('Set-Cookie', f"session={barebones_web_authentication.sign_dict(session)}; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ])
    return [data]


# compact router for serving multiple web pages for a wsgi app a(add auth URLS to this list)
URLS = barebones_web_authentication.URLS + [
    (r"^/$", homepage_view),
    (r"^/counter$", counter_view),
    (r"^/admin$", admin_view),
]
def router(e, sr):
    import re
    return next(
        (v for u, v in URLS if re.search(u, (e.get("PATH_INFO") or "/"))),
        lambda i, j: [j("404 Not Found", [("Content-Type", "text/plain"), ("Content-Length", "13")]), [b"404 Not Found"]][-1]
    )(e, sr)

# standalone WSGI web server (e.g. `python3 demo.py`)
if __name__ == '__main__':
    import sys
    from wsgiref.simple_server import make_server
    host, port = next(iter(sys.argv[1:]), "127.0.0.1"), int(next(iter(sys.argv[2:]), "8000"))
    print(f"Serving HTTP on {host}:{port}... (Ctrl+c to quit)")
    make_server(host, port, router).serve_forever()
