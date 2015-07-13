"""django.contrib.auth.tokens, but without using last_login in hash"""

from datetime import date
from django.conf import settings
from django.utils.http import int_to_base36, base36_to_int
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils import six
from django.contrib.auth.hashers import make_password
import base64


class PasswordResetTokenGenerator(object):
    """
    Strategy object used to generate and check tokens for the password
    reset mechanism.
    """
    def make_token(self, user):
        """
        Returns a token that can be used once to do a password reset
        for the given user.
        """
        user.password = None
        return self._make_token_with_timestamp(user, self._num_days(self._today()))

    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user.
        """
        # Parse the token
        try:
            ts_b36, hashval = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        expiretime = getattr(settings, 'TOKEN_TIMEOUT_DAYS', 7)
        if expiretime:
            expiretime = int(expiretime)
            if expiretime > 0:
                # Check the timestamp is within limit
                if (self._num_days(self._today()) - ts) > expiretime:
                    return False
        return True


    def _make_token_with_timestamp(self, user, timestamp):
        # timestamp is number of days since 2001-1-1.  Converted to
        # base 36, this gives us a 3 digit string until about 2121
        ts_b36 = int_to_base36(timestamp)

        if not user.password: 
            password = make_password(None)
            key_salt = make_password(None)
            key_salt = base64.b64encode(salted_hmac(six.text_type(user.pk), key_salt).hexdigest())
            user.password = "%s$%s"%(password, key_salt)
            user.save()
        else:
            password, key_salt = user.password.split("$")
        value = (six.text_type(user.pk) + user.password + six.text_type(timestamp))
        hashval = salted_hmac(key_salt, value).hexdigest()        
        return base64.urlsafe_b64encode("%s-%s" % (ts_b36,hashval))


    def _num_days(self, dt):
        return (dt - date(2001, 1, 1)).days


    def _today(self):
        # Used for mocking in tests
        return date.today()


token_generator = PasswordResetTokenGenerator()
