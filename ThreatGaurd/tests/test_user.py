import unittest
import models
import os


class TestUserAuthentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use a separate test to avoid affecting real user data
        cls.test_db_path = "database/test_users.db"
        models.DB_PATH = cls.test_db_path
        models.initialize_user_db()  # Initialise the test database

    @classmethod
    def tearDownClass(cls):
        # Clean up test database after tests (error here)
        if os.path.exists(cls.test_db_path):
            os.remove(cls.test_db_path)

    def test_register_user_success(self):
        result = models.register_user("test_user", "StrongPass1!")
        self.assertTrue(result)

    def test_register_existing_user(self):
        models.register_user("test_user", "StrongPass1!")
        result = models.register_user("test_user", "StrongPass1!")  # attempt duplicate
        self.assertFalse(result)

    def test_login_user_success(self):
        models.register_user("test_user", "StrongPass1!")
        authenticated = models.authenticate_user("test_user", "StrongPass1!")
        self.assertTrue(authenticated)

    def test_login_invalid_credentials(self):
        models.register_user("test_user", "StrongPass1!")
        authenticated = models.authenticate_user("wrong_user", "wrongpass")
        self.assertFalse(authenticated)

    def test_register_weak_password(self):
        result = models.register_user("weak_user", "weak")
        self.assertFalse(result)

    def test_register_empty_username(self):
        result = models.register_user("", "StrongPass1!")
        self.assertFalse(result)

    def test_register_empty_password(self):
        result = models.register_user("test_user2", "")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
