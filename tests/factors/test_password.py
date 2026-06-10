import typing

import pytest

from aegistry.factors.password import (
    PasswordAlreadyEnrolledException,
    PasswordEnrollment,
    PasswordFactor,
    PasswordNotEnrolledException,
)


class InMemoryPasswordFactor(PasswordFactor):
    def __init__(self, **kwargs: typing.Any) -> None:
        self.storage: dict[int, PasswordEnrollment] = {}
        self._id = 0
        super().__init__(**kwargs)

    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> PasswordEnrollment | None:
        for enrollment in self.storage.values():
            if enrollment.identity_id == identity_id:
                return enrollment
        return None

    async def insert(self, enrollment: PasswordEnrollment) -> int:
        self._id += 1
        self.storage[self._id] = enrollment
        return self._id

    async def update(self, enrollment: PasswordEnrollment) -> None:
        assert enrollment.id is not None
        self.storage[enrollment.id] = enrollment

    async def delete(self, enrollment: PasswordEnrollment) -> None:
        assert enrollment.id is not None
        del self.storage[enrollment.id]


@pytest.fixture
def password_factor() -> InMemoryPasswordFactor:
    return InMemoryPasswordFactor()


@pytest.mark.anyio
class TestEnroll:
    async def test_enroll(self, password_factor: InMemoryPasswordFactor) -> None:
        enrollment = await password_factor.enroll(42, "herminetincture")

        assert enrollment.id == 1
        assert enrollment.identity_id == 42
        assert enrollment.hash != "herminetincture"

    async def test_already_enrolled(
        self, password_factor: InMemoryPasswordFactor
    ) -> None:
        await password_factor.enroll(42, "herminetincture")

        with pytest.raises(PasswordAlreadyEnrolledException):
            await password_factor.enroll(42, "herminetincture")


@pytest.mark.anyio
class TestAuthenticate:
    async def test_valid_password(
        self, password_factor: InMemoryPasswordFactor
    ) -> None:
        await password_factor.enroll(42, "herminetincture")

        enrollment = await password_factor.authenticate(42, "herminetincture")

        assert enrollment is not None
        assert enrollment.identity_id == 42

    async def test_invalid_password(
        self, password_factor: InMemoryPasswordFactor
    ) -> None:
        await password_factor.enroll(42, "herminetincture")

        enrollment = await password_factor.authenticate(42, "wrong")

        assert enrollment is None

    async def test_not_enrolled(self, password_factor: InMemoryPasswordFactor) -> None:
        enrollment = await password_factor.authenticate(42, "herminetincture")

        assert enrollment is None

    async def test_unknown_identity(
        self, password_factor: InMemoryPasswordFactor
    ) -> None:
        enrollment = await password_factor.authenticate(None, "herminetincture")

        assert enrollment is None


@pytest.mark.anyio
class TestChange:
    async def test_change(self, password_factor: InMemoryPasswordFactor) -> None:
        await password_factor.enroll(42, "herminetincture")

        await password_factor.change(42, "newpassword123")

        assert await password_factor.authenticate(42, "herminetincture") is None
        assert await password_factor.authenticate(42, "newpassword123") is not None

    async def test_not_enrolled(self, password_factor: InMemoryPasswordFactor) -> None:
        with pytest.raises(PasswordNotEnrolledException):
            await password_factor.change(42, "newpassword123")
