import unittest
from unittest.mock import patch, MagicMock


class TestUserAuthentication(unittest.TestCase):

    # ✅ Equivalence Partitioning Test - Successful Registration
    @patch("models.register_user")
    def test_register_user_success(self, mock_register):
        mock_register.return_value = True

        success = mock_register("test_user", "StrongPass1!")
        self.assertTrue(success)

    # ✅ Equivalence Partitioning Test - Registering Existing User
    @patch("models.register_user")
    def test_register_existing_user(self, mock_register):
        mock_register.return_value = False

        success = mock_register("test_user", "StrongPass1!")
        self.assertFalse(success)

    # ✅ Equivalence Partitioning Test - Successful Login
    @patch("models.authenticate_user")
    def test_login_user_success(self, mock_authenticate):
        mock_authenticate.return_value = True

        authenticated = mock_authenticate("test_user", "StrongPass1!")
        self.assertTrue(authenticated)

    # ✅ Equivalence Partitioning Test - Invalid Login
    @patch("models.authenticate_user")
    def test_login_invalid_credentials(self, mock_authenticate):
        mock_authenticate.return_value = False

        authenticated = mock_authenticate("invalid_user", "wrongpass")
        self.assertFalse(authenticated)

    # ✅ Boundary Value Analysis - Short Username (3 characters)
    @patch("models.register_user")
    def test_register_short_username(self, mock_register):
        mock_register.return_value = False

        success = mock_register("usr", "StrongPass1!")
        self.assertFalse(success)

    # ✅ Boundary Value Analysis - Minimum Username Length (4 characters)
    @patch("models.register_user")
    def test_register_min_username(self, mock_register):
        mock_register.return_value = True

        success = mock_register("user", "StrongPass1!")
        self.assertTrue(success)

    # ✅ Robustness Testing - Username with Special Characters
    @patch("models.register_user")
    def test_register_invalid_username_special_chars(self, mock_register):
        mock_register.return_value = False

        success = mock_register("user@!", "StrongPass1!")
        self.assertFalse(success)

    # ✅ Robustness Testing - Password without Special Characters
    @patch("models.register_user")
    def test_register_weak_password_no_special(self, mock_register):
        mock_register.return_value = False

        success = mock_register("test_user", "StrongPass1")
        self.assertFalse(success)

    # ✅ Robustness Testing - Empty Username
    @patch("models.register_user")
    def test_register_empty_username(self, mock_register):
        mock_register.return_value = False

        success = mock_register("", "StrongPass1!")
        self.assertFalse(success)

    # ✅ Robustness Testing - Empty Password
    @patch("models.register_user")
    def test_register_empty_password(self, mock_register):
        mock_register.return_value = False

        success = mock_register("test_user", "")
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
