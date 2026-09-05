# Description: Unit tests for user registration, regex validation, and 3-Factor Authentication (3FA) flow.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from models.user import User
from services.auth_service import (
    validate_registration_inputs,
    register_user,
    start_3fa_login,
    verify_3fa_factor2,
    verify_3fa_factor3,
    get_totp_token,
    verify_totp_token,
    PENDING_3FA_SESSIONS,
    complete_password_reset,
)
from services.mail_server import RECEIVED_EMAILS


class TestAuthAnd3FA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        cls.Session = sessionmaker(bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_registration_regex_validation(self):
        # Valid credentials
        ok, err = validate_registration_inputs("valid_user-1", "test@domain.com", "StrongPass123!")
        self.assertTrue(ok)
        self.assertIsNone(err)

        # Invalid username (too short or special chars)
        ok, err = validate_registration_inputs("a", "test@domain.com", "StrongPass123!")
        self.assertFalse(ok)

        # Invalid email
        ok, err = validate_registration_inputs("valid_user", "not-an-email", "StrongPass123!")
        self.assertFalse(ok)

        # Weak password (no uppercase or digits or special chars)
        ok, err = validate_registration_inputs("valid_user", "test@domain.com", "weakpass")
        self.assertFalse(ok)

    def test_full_3fa_lifecycle(self):
        # 1. Register User
        user, err = register_user(self.db, "test_3fa_user", "test3fa@cryptomail.local", "SuperSecure123!")
        self.assertIsNone(err)
        self.assertIsNotNone(user)
        self.assertEqual(len(user.recovery_codes_list), 8)

        # 2. Factor 1: Login check
        session_id, logged_user, err = start_3fa_login(self.db, "test_3fa_user", "SuperSecure123!")
        self.assertIsNone(err)
        self.assertIsNotNone(session_id)
        self.assertEqual(logged_user.id, user.id)

        # 3. Factor 2: Verify email OTP code received in local SMTP inbox
        self.assertTrue(len(RECEIVED_EMAILS) > 0)
        otp = PENDING_3FA_SESSIONS[session_id]["otp"]
        ok, err = verify_3fa_factor2(session_id, otp)
        self.assertTrue(ok)

        # 4. Factor 3: Verify using TOTP token
        totp_code = get_totp_token(user.totp_secret)
        authenticated_user, err = verify_3fa_factor3(self.db, session_id, totp_code)
        self.assertIsNone(err)
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.username, "test_3fa_user")

    def test_factor3_recovery_code(self):
        # Test Factor 3 with single-use recovery code
        user, _ = register_user(self.db, "rec_user", "rec@cryptomail.local", "SuperSecure123!")
        code = user.recovery_codes_list[0]

        session_id, _, _ = start_3fa_login(self.db, "rec_user", "SuperSecure123!")
        otp = PENDING_3FA_SESSIONS[session_id]["otp"]
        verify_3fa_factor2(session_id, otp)

        # Submit recovery code
        auth_user, err = verify_3fa_factor3(self.db, session_id, code)
        self.assertIsNone(err)
        self.assertIsNotNone(auth_user)

        # Ensure code was consumed (now only 7 codes left)
        self.db.refresh(user)
        self.assertEqual(len(user.recovery_codes_list), 7)
        self.assertNotIn(code, user.recovery_codes_list)

    def test_password_recovery(self):
        user, _ = register_user(self.db, "reset_user", "reset@cryptomail.local", "SuperSecure123!")
        rec_code = user.recovery_codes_list[0]

        # Reset password using recovery code
        ok, err = complete_password_reset(self.db, None, "reset_user", rec_code, "BrandNewPass999#")
        self.assertTrue(ok)

        # Verify old password fails
        _, _, err = start_3fa_login(self.db, "reset_user", "SuperSecure123!")
        self.assertIsNotNone(err)

        # Verify new password succeeds
        _, user_new, err = start_3fa_login(self.db, "reset_user", "BrandNewPass999#")
        self.assertIsNone(err)
        self.assertIsNotNone(user_new)


if __name__ == "__main__":
    unittest.main()
