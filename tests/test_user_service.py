import pytest
from app.db.models.rbac import User
from app.services.user_service import UserService
from app.core.config import settings


@pytest.fixture
def mock_bcrypt_context(mocker):
    """Mock the bcrypt context for hashing and verifying passwords."""
    mock_context = mocker.patch("app.core.config.Settings.bcrypt_context", autospec=True)
    mock_context.hash.return_value = "hashed_password"
    mock_context.verify.return_value = True
    return mock_context


def test_set_password(mock_bcrypt_context):
    """Test the set_password method."""
    user = User(username="testuser")
    password = "securepassword"

    # Call the method
    UserService.set_password(user, password)

    # Verify the password was hashed and set
    mock_bcrypt_context.hash.assert_called_once_with(password)
    assert user.hashed_password == "hashed_password"


def test_check_password(mock_bcrypt_context):
    """Test the check_password method."""
    user = User(username="testuser", hashed_password="hashed_password")
    password = "securepassword"

    # Call the method
    result = UserService.check_password(user, password)

    # Verify the password was checked
    mock_bcrypt_context.verify.assert_called_once_with(password, "hashed_password")
    assert result is True


def test_check_password_incorrect(mock_bcrypt_context):
    """Test the check_password method with an incorrect password."""
    mock_bcrypt_context.verify.return_value = False
    user = User(username="testuser", hashed_password="hashed_password")
    password = "wrongpassword"

    # Call the method
    result = UserService.check_password(user, password)

    # Verify the password was checked and failed
    mock_bcrypt_context.verify.assert_called_once_with(password, "hashed_password")
    assert result is False