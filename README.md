# Python barebones web authentication framework

This is a set of WSGI views and utilities that can be used to add user authentication to WSGI apps in python.

It is a single file that has no dependencies other than the `python3` and `openssl` (which tend to be already installed on most web servers), so there's no requirement to setup a virtualenv/venv/etc. to install dependencies. To customize the behavior or design, just edit the code directly (it's one file). 

I made this to quickly add authenticated pages to my small hobby WSGI web applications for a known set of pre-defined users. Most servers have python3 and openssl already installed, and I don't want to have to fuss about with a virtualenv.

## THIS IS NOT A ROBUST AUTHENTICATION FRAMEWORK

**DO NOT USE THIS FOR ANYTHING IMPORTANT!**

This authentication framework is intended for hobby and small projects that don't have anything too important behind the authentication wall.

It does NOT have robust authentication features in it, such as rate limiting login attempts, password resets, lockout after too many failed attempts, etc.

## How to use

See  `demo.py` for how to integrate the framework into a wsgi app.

## License

Released under MIT License.
