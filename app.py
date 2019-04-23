#!/usr/bin/env python3

import bottle
from bottle import get, post, static_file, request, route, template
from bottle import SimpleTemplate
from configparser import ConfigParser
from ldap3 import Connection, Server
from ldap3 import SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPConstraintViolationResult, \
    LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError, \
    LDAPSocketOpenError, LDAPExceptionError
import logging
import os
from os import environ, path

import smtplib
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer


BASE_DIR = path.dirname(__file__)
LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s'
VERSION = '2.1.0'


@get('/')
def get_index():
    return index_tpl()


@post('/')
def post_index():
    form = request.forms.getunicode

    def error(msg):
        return index_tpl(username=form('username'), alerts=[('error', msg)])

    if len(form('new-password')) < 1 or len(form('old-password')) < 1:
        return error("The password fields are required!")

    if form('new-password') != form('confirm-password'):
        return error("Password doesn't match the confirmation!")

    if len(form('new-password')) < 8:
        return error("Password must be at least 8 characters long!")

    try:
        change_passwords(form('username'), form('old-password'), form('new-password'))
    except Error as e:
        LOG.warning("Unsuccessful attempt to change password for %s: %s" % (form('username'), e))
        return error(str(e))

    LOG.info("Password successfully changed for: %s" % form('username'))

    return index_tpl(alerts=[('success', "Password has been changed")])


@post('/reset')
def send_password_reset_email():
    form = request.forms.getunicode

    mail = check_user_mail(form('username'))

    if mail:
        password_reset_serializer = URLSafeTimedSerializer(CONF['app']['secret_key'])
        password_reset_url = bottle.default_app().get_url(
            'reset_with_token',
            token = password_reset_serializer.dumps(form('username'), salt='mmmmhm-soooo-salty'))

        try:
            send_email(password_reset_url, mail)
            LOG.info("Password reset request has been sent to: %s" % mail)
        except:
            LOG.warning("Password reset request could NOT be sent to: %s" % mail)
    else:
        LOG.warning("Could not find email address for user: %s" % form('username'))
    return index_tpl(alerts=[('success', "Sending password reset request...")])

def send_email(password_reset_url, mail):
    msg = EmailMessage()
    msg['Subject'] = 'Password reset request'
    msg['From'] = 'ldappw@spie.com'
    msg['To'] = mail
    msg.set_content(CONF['app']['base_url'] + password_reset_url)

    s = smtplib.SMTP(CONF['app']['mail_relay'])
    s.send_message(msg)
    s.quit()


@get('/reset/<token>')
def reset(token):
    return reset_tpl()


@post('/reset/<token>', name='reset_with_token')
def reset_with_token(token):
    form = request.forms.getunicode

    try:
        password_reset_serializer = URLSafeTimedSerializer(CONF['app']['secret_key'])
        username = password_reset_serializer.loads(token, salt='mmmmhm-soooo-salty', max_age=3600)

        if form('new-password') != form('confirm-password'):
            return reset_tpl(alerts=[('error', "Password doesn't match the confirmation!")])

        with connect_ldap(CONF['ldap:0'], authentication=SIMPLE, user=CONF['app']['admin_user'], password=CONF['app']['admin_pass']) as c:
            c.bind()
            user_dn = find_user_dn(CONF['ldap:0'], c, username)
            c.extend.microsoft.modify_password(user_dn, form('new-password'))

        LOG.info("Password has been reseted for user: %s" % username)
        return reset_tpl(alerts=[('success', "New password has been set")])
    except:
        LOG.warning("Password could NOT be reseted for user: %s" % username)
        return reset_tpl(alerts=[('error', "Oops, something went wrong :(")])


@route('/static/<filename>', name='static')
def serve_static(filename):
    return static_file(filename, root=path.join(BASE_DIR, 'static'))


def index_tpl(**kwargs):
    return template('index', **kwargs)

def reset_tpl(**kwargs):
    return template('reset', **kwargs)


def connect_ldap(conf, **kwargs):
    server = Server(host=conf['host'],
                    port=conf.getint('port', None),
                    use_ssl=conf.getboolean('use_ssl', False),
                    connect_timeout=5)

    return Connection(server, raise_exceptions=True, **kwargs)


def change_passwords(username, old_pass, new_pass):
    changed = []

    for key in (key for key in CONF.sections()
                if key == 'ldap' or key.startswith('ldap:')):

        LOG.debug("Changing password in %s for %s" % (key, username))
        try:
            change_password(CONF[key], username, old_pass, new_pass)
            changed.append(key)
        except Error as e:
            for key in reversed(changed):
                LOG.info("Reverting password change in %s for %s" % (key, username))
                try:
                    change_password(CONF[key], username, new_pass, old_pass)
                except Error as e2:
                    LOG.error('{}: {!s}'.format(e.__class__.__name__, e2))
            raise e


def change_password(conf, *args):
    try:
        if conf.get('type') == 'ad':
            change_password_ad(conf, *args)
        else:
            change_password_ldap(conf, *args)

    except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
        raise Error('Username or password is incorrect!')

    except LDAPConstraintViolationResult as e:
        # Extract useful part of the error message (for Samba 4 / AD).
        msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
        raise Error(msg)

    except LDAPSocketOpenError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Unable to connect to the remote server.')

    except LDAPExceptionError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Encountered an unexpected error while communicating with the remote server.')


def change_password_ldap(conf, username, old_pass, new_pass):

    if conf.get('force_auth') == 'true':
        with connect_ldap(conf, authentication=SIMPLE, user=CONF['app']['admin_user'], password=CONF['app']['admin_pass']) as c:
            user_dn = find_user_dn(conf, c, username)
    else:
        with connect_ldap(conf) as c:
            user_dn = find_user_dn(conf, c, username)

    # Note: raises LDAPUserNameIsMandatoryError when user_dn is None.
    with connect_ldap(conf, authentication=SIMPLE, user=user_dn, password=old_pass) as c:
        c.bind()
        c.extend.standard.modify_password(user_dn, old_pass, new_pass)


def change_password_ad(conf, username, old_pass, new_pass):
    user = username + '@' + conf['ad_domain']

    with connect_ldap(conf, authentication=SIMPLE, user=user, password=old_pass) as c:
        c.bind()
        user_dn = find_user_dn(conf, c, username)
        c.extend.microsoft.modify_password(user_dn, new_pass, old_pass)


def find_user_dn(conf, conn, uid):
    search_filter = conf['search_filter'].replace('{uid}', uid)
    conn.search(conf['base'], "(%s)" % search_filter, SUBTREE)

    return conn.response[0]['dn'] if conn.response else None

def check_user_mail(username):
    with connect_ldap(CONF['ldap:0'], authentication=SIMPLE, user=CONF['app']['admin_user'], password=CONF['app']['admin_pass']) as c:
        c.bind()
        c.search(CONF['ldap:0']['base'], "(cn=%s)" % username, SUBTREE, attributes=['mail'])

        return c.response[0]['attributes']['mail'] if 'attributes' in c.response[0] else None

def read_config():
    config = ConfigParser()
    config.read([path.join(BASE_DIR, 'settings.ini'), os.getenv('CONF_FILE', '')])

    return config


class Error(Exception):
    pass


if environ.get('DEBUG'):
    bottle.debug(True)

# Set up logging.
logging.basicConfig(format=LOG_FORMAT)
LOG.setLevel(logging.INFO)
LOG.info("Starting ldap-passwd-webui %s" % VERSION)

CONF = read_config()

bottle.TEMPLATE_PATH = [BASE_DIR]

# Set default attributes to pass into templates.
SimpleTemplate.defaults = dict(CONF['html'])
SimpleTemplate.defaults['url'] = bottle.url


# Run bottle internal server when invoked directly (mainly for development).
if __name__ == '__main__':
    bottle.run(**CONF['server'])
# Run bottle in application mode (in production under uWSGI server).
else:
    application = bottle.default_app()
