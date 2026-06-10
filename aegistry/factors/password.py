"""Password authentication factor.

Hashing is delegated to `pwdlib <https://github.com/frankie567/pwdlib>`_,
which defaults to Argon2id. Install the optional dependency with
``pip install "aegistry[password]"``.
"""

import abc
import dataclasses
import secrets
import typing

from aegistry.amr import AuthenticationMethodReference
from aegistry.exceptions import AegistryException
from aegistry.factors.base import FactorBase
from aegistry.logging import get_logger

try:
    from pwdlib import PasswordHash
except ModuleNotFoundError as e:  # pragma: no cover
    raise ModuleNotFoundError(  # noqa: TRY003
        "The password factor requires pwdlib. "
        'Install it with: pip install "aegistry[password]"'
    ) from e

logger = get_logger(__name__)


@dataclasses.dataclass
class PasswordEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    hash: str


class PasswordException(AegistryException):
    """Base exception for password factor errors."""


class PasswordAlreadyEnrolledException(PasswordException):
    """Raised when trying to enroll a password for an identity that already has one."""


class PasswordNotEnrolledException(PasswordException):
    """Raised when an operation requires an existing password enrollment."""


class PasswordFactor(FactorBase[PasswordEnrollment]):
    """Password factor.

    Verification is timing-safe with respect to user existence: when no
    enrollment is found, a dummy hash is still verified so that response
    times don't leak whether an identity has a password enrolled.
    """

    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.PWD
    )

    def __init__(
        self,
        *,
        identifier: str = "password",
        step: int = 0,
        password_hash: PasswordHash | None = None,
    ) -> None:
        """
        Initialize the password factor.

        Args:
            identifier: A unique identifier for the factor.
            step: The authentication step at which this factor can be used.
            password_hash: A pwdlib PasswordHash instance. Defaults to
                ``PasswordHash.recommended()`` (Argon2id).
        """
        super().__init__(identifier=identifier, step=step)
        self.password_hash = password_hash or PasswordHash.recommended()
        self._dummy_hash = self.password_hash.hash(secrets.token_urlsafe(32))

    async def enroll(
        self, identity_id: typing.Any, password: str
    ) -> PasswordEnrollment:
        """
        Enroll a password for an identity.

        Args:
            identity_id: The ID of the identity to enroll.
            password: The plaintext password to hash and store.

        Returns:
            The newly created PasswordEnrollment instance.

        Raises:
            PasswordAlreadyEnrolledException: If the identity already has a password.
        """
        logger.debug("Password enroll attempted", extra={"identity_id": identity_id})
        existing = await self.get_enrollment(identity_id)
        if existing is not None:
            raise PasswordAlreadyEnrolledException()

        enrollment = PasswordEnrollment(
            id=None,
            identity_id=identity_id,
            hash=self.password_hash.hash(password),
        )
        enrollment.id = await self.insert(enrollment)
        logger.info(
            "Password enrollment created",
            extra={"enrollment_id": enrollment.id, "identity_id": identity_id},
        )
        return enrollment

    async def authenticate(
        self, identity_id: typing.Any, password: str
    ) -> PasswordEnrollment | None:
        """
        Verify a password for an identity.

        If the stored hash uses outdated parameters, it is transparently
        re-hashed and persisted on successful verification.

        Args:
            identity_id: The ID of the identity to authenticate.
            password: The plaintext password to verify.

        Returns:
            The PasswordEnrollment if the password is valid, None otherwise.
        """
        logger.debug(
            "Password authentication attempted", extra={"identity_id": identity_id}
        )
        enrollment = await self.get_enrollment(identity_id)
        if enrollment is None:
            # Burn comparable CPU time so response timing doesn't reveal
            # whether the identity has a password enrolled.
            self.password_hash.verify(password, self._dummy_hash)
            logger.warning(
                "Password authentication failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            return None

        valid, updated_hash = self.password_hash.verify_and_update(
            password, enrollment.hash
        )
        if not valid:
            logger.warning(
                "Password authentication failed: invalid password",
                extra={"identity_id": identity_id},
            )
            return None

        if updated_hash is not None:
            enrollment.hash = updated_hash
            await self.update(enrollment)
            logger.info(
                "Password hash upgraded",
                extra={"enrollment_id": enrollment.id, "identity_id": identity_id},
            )

        logger.info(
            "Password authentication succeeded", extra={"identity_id": identity_id}
        )
        return enrollment

    async def change(
        self, identity_id: typing.Any, new_password: str
    ) -> PasswordEnrollment:
        """
        Change the password of an identity.

        The caller is responsible for re-authenticating the user beforehand
        and for revoking existing sessions afterwards.

        Args:
            identity_id: The ID of the identity whose password to change.
            new_password: The new plaintext password.

        Returns:
            The updated PasswordEnrollment instance.

        Raises:
            PasswordNotEnrolledException: If the identity has no password enrolled.
        """
        enrollment = await self.get_enrollment(identity_id)
        if enrollment is None:
            raise PasswordNotEnrolledException()

        enrollment.hash = self.password_hash.hash(new_password)
        await self.update(enrollment)
        logger.info(
            "Password changed",
            extra={"enrollment_id": enrollment.id, "identity_id": identity_id},
        )
        return enrollment

    @abc.abstractmethod
    async def insert(self, enrollment: PasswordEnrollment) -> typing.Any:
        """
        Insert a password enrollment into a persistent store.

        Args:
            enrollment: The PasswordEnrollment instance to insert.

        Returns:
            The ID of the inserted PasswordEnrollment.
        """
        ...

    @abc.abstractmethod
    async def update(self, enrollment: PasswordEnrollment) -> None:
        """
        Update a password enrollment in a persistent store.

        Args:
            enrollment: The PasswordEnrollment instance to update.
        """
        ...

    @abc.abstractmethod
    async def delete(self, enrollment: PasswordEnrollment) -> None:
        """
        Delete a password enrollment from a persistent store.

        Args:
            enrollment: The PasswordEnrollment instance to delete.
        """
        ...
