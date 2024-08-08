import base64
import io
import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass, asdict
from encryptor import signature, encrypt, decrypt
from pathlib import Path
from random import random, randint
from typing import Generator


class WrongPin(ValueError):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class WrongPassword(ValueError):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


@dataclass
class Value:
    value: str | int | float | bool | None = None
    masked: bool = False

    def __repr__(self) -> str:
        if self.masked:
            return f"Value(*masked*)"
        return f"Value({repr(self.value)})"


class Data:
    _salt = b"\x08t>~\xb6\x81\xf1\x16\xc51 \xb8'n\x9c\xb1"
    iter_count_bytes_len = 4
    pin_bytes_len = 4

    def __init__(
            self,
            name: str,
            description: str = "",
            data: list[tuple[str, Value]] | dict[str, Value] | None = None,
            iter_count: int = 100_000
            ) -> None:
        self.name = name
        self.description = description

        self._data = None
        self.data = data

        self.iter_count = iter_count

    def __repr__(self) -> str:
        return f"Data(name={repr(self.name)})"

    @property
    def data(self) -> OrderedDict[str, Value]:
        return self._data

    @data.setter
    def data(
            self,
            value: list[tuple[str, Value]] | dict[str, Value] | None = None
            ) -> None:
        if value is None:
            value = []
        value = OrderedDict(value)
        for key, val in value.items():
            if not isinstance(val, Value):
                val = Value(val)
            value[key] = val
        self._data = value

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "data": [
                [key, asdict(value)]
                for key, value in self.data.items()
            ]
        }

    @classmethod
    def from_dict(cls, _obj: dict[str, str | int | float | bool | None]):
        return cls(
            name=_obj["name"],
            description=_obj["description"],
            data=[
                (key, Value(**value))
                for key, value in _obj["data"]
            ]
        )

    def random_iter_count(self, jitter: float = 0.1):
        return randint(
            int(self.iter_count * (1 - jitter)),
            int(self.iter_count * (1 + jitter))
        )

    def password_encrypt(
            self,
            password: str
            ) -> "Data":
        data = json.dumps(self.to_dict()["data"]).encode()
        password: bytes = password.encode()
        iter_count = self.random_iter_count()

        password_encrypted = encrypt(
            data,
            password,
            self._salt,
            iter_count
        )

        iter_count = iter_count.to_bytes(self.iter_count_bytes_len, "big")
        encrypted_data = base64.b64encode(iter_count + password_encrypted).decode()
        return Data(
            name=self.name,
            description=self.description,
            data={
                "encrypted_data": encrypted_data
            }
        )

    def pin_encrypt(
            self,
            password_encrypted_data: "Data",
            username: str,
            pin: int
            ) -> bytes:
        pin: bytes = pin.to_bytes(self.pin_bytes_len, "big")
        iter_count = self.random_iter_count()

        pin_encrypted = encrypt(
            json.dumps(password_encrypted_data.to_dict()).encode(),
            pin,
            self._salt,
            iter_count
        )

        username_signature = signature(
            username,
            self._salt,
            iter_count
        )
        name_signature = signature(
            password_encrypted_data.name,
            self._salt,
            iter_count
        )
        iter_count = iter_count.to_bytes(self.iter_count_bytes_len, "big")
        return username_signature + iter_count + name_signature + pin_encrypted

    def encrypt(
            self,
            username: str,
            pin: int,
            password: str
            ) -> bytes:
        password_encrypted_data = self.password_encrypt(password)
        return self.pin_encrypt(password_encrypted_data, username, pin)

    @classmethod
    def pin_decrypt(
            cls,
            pin_encrypted: io.BytesIO,
            username: str,
            pin: int,
            name: str | None = None
            ) -> "Data":
        pin: bytes = pin.to_bytes(cls.pin_bytes_len, "big")

        username_signature = pin_encrypted.read(32)
        iter_count = int.from_bytes(pin_encrypted.read(cls.iter_count_bytes_len), "big")
        if iter_count == 0 \
                or signature(username, cls._salt, iter_count) != username_signature:
            raise ValueError("Signature check failed")

        name_signature = pin_encrypted.read(32)
        if name is not None \
                and signature(name, cls._salt, iter_count) != name_signature:
            raise ValueError("Signature check failed")

        try:
            data = decrypt(
                pin_encrypted.read(),
                pin,
                cls._salt,
                iter_count
            )
        except:
            raise WrongPin()

        return cls.from_dict(json.loads(data))

    @classmethod
    def password_decrypt(
            cls,
            password_encrypted_data: "Data",
            password: str
            ) -> "Data":
        password: bytes = password.encode()
        password_encrypted = base64.b64decode(
            password_encrypted_data.data["encrypted_data"].value
        )
        iter_count = int.from_bytes(password_encrypted[:cls.iter_count_bytes_len], "big")

        try:
            data = decrypt(
                password_encrypted[cls.iter_count_bytes_len:],
                password,
                cls._salt,
                iter_count
            )

        except:
            raise WrongPassword()

        return Data.from_dict({
            "name": password_encrypted_data.name,
            "description": password_encrypted_data.description,
            "data": json.loads(data)
        })

    @classmethod
    def from_decrypt(
            cls,
            pin_encrypted: io.BytesIO,
            username: str,
            pin: int,
            password: str
            ) -> "Data":
        password_encrypted_data = cls.pin_decrypt(pin_encrypted, username, pin)
        return cls.password_decrypt(password_encrypted_data, password)


class DataManager:
    def __init__(
            self,
            store_dir: str | Path
            ) -> None:
        if not isinstance(store_dir, Path):
            store_dir = Path(store_dir)
        self.store_dir = store_dir

    def iter(
            self,
            username: str,
            pin: int,
            password: str | None = None,
            name: str | None = None,
            exclude_dummy: bool = True
            ) -> Generator[tuple[Path, Data], None, None]:
        for encrypted_file_path in self.store_dir.glob(".*"):
            if not encrypted_file_path.is_file():
                continue

            with open(encrypted_file_path, "rb") as f:
                try:
                    password_encrypted_data = Data.pin_decrypt(f, username, pin, name)
                except ValueError:
                    continue

            if exclude_dummy and self.is_dummy(password_encrypted_data.name):
                continue

            if password is not None:
                data = Data.password_decrypt(
                    password_encrypted_data,
                    password
                )
            else:
                data = password_encrypted_data

            yield encrypted_file_path, data

    def create_dummy(self, item_count: int = 2) -> Data:
        return Data(
            f"dummy-{uuid.uuid4()}",
            data=[
                (f"key{i}", str(uuid.uuid4()))
                for i in range(item_count)
            ]
        )

    def add(
            self,
            data: Data,
            username: str,
            pin: int,
            password: str,
            dummy: int = 0
        ) -> None:
        assert isinstance(data, Data)
        encrypted_data = data.encrypt(username, pin, password)
        encrypted_dummies = [
            self.create_dummy().encrypt(username, pin, str(uuid.uuid4()))
            for _ in range(dummy)
        ]

        mixed_data = sorted(
            [encrypted_data] + encrypted_dummies,
            key=lambda _: random()
        )
        for data in mixed_data:
            with open(f".{uuid.uuid4()}", "wb") as f:
                f.write(data)

    def delete(self, file_path: Path):
        file_path.unlink()

    @staticmethod
    def is_dummy(name: str) -> bool:
        return name.startswith("dummy-") and len(name) == 42
