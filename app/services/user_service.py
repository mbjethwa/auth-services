from app.core.config import settings
from app.db.models.rbac import User


class UserService:
    @staticmethod
    def set_password(user: User, password: str) -> None:
        user.hashed_password = settings.bcrypt_context.hash(password)

    @staticmethod
    def check_password(user: User, password: str) -> bool:
        return settings.bcrypt_context.verify(password, user.hashed_password)


# Example Usage
# user = User(username="example")
# UserService.set_password(user, "securepassword")
# is_correct = UserService.check_password(user, "securepassword")
