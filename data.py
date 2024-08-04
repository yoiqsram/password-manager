import base64
import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass, asdict
from encryptor import encrypt, decrypt
from hashlib import sha256
from pathlib import Path
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
    iter_count_bytes_len = 4
    pin_bytes_len = 4

    def __init__(
            self,
            name: str,
            description: str = "",
            data: list[tuple[str, Value]] | dict[str, Value] | None = None,
            iter_count: int = 1_000_000
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

    def encrypt(self, pin: int, password: str) -> bytes:
        pin: bytes = pin.to_bytes(self.pin_bytes_len)
        password: bytes = password.encode()

        data = json.dumps(self.to_dict()["data"]).encode()
        password_encrypted = encrypt(
            data,
            password,
            self.iter_count
        )
        password_encrypted = base64.b64encode(password_encrypted).decode()

        password_encrypted_wrapper = (
            json.dumps({
                "name": self.name,
                "description": self.description,
                "data": password_encrypted
            })
            .encode()
        )
        pin_encrypted = encrypt(
            password_encrypted_wrapper,
            pin,
            self.iter_count
        )

        checksum = sha256(pin_encrypted).digest()
        iter_count = self.iter_count.to_bytes(self.iter_count_bytes_len)
        return checksum + iter_count + pin_encrypted

    def encrypt_dump(
            self,
            file_path: Path,
            pin: int,
            password: str
            ) -> None:
        encrypted_data = self.encrypt(pin, password)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)

    @classmethod
    def pin_decrypt(
            cls,
            encrypted_data: bytes,
            pin: int
            ) -> tuple[dict[str, str | bytes], int]:
        checksum = encrypted_data[:32]
        iter_count = int.from_bytes(encrypted_data[32:32 + cls.iter_count_bytes_len])
        pin_encrypted = encrypted_data[32 + cls.iter_count_bytes_len:]
        pin: bytes = pin.to_bytes(cls.pin_bytes_len)

        checksum_ = sha256(pin_encrypted).digest()
        if checksum != checksum_:
            raise ValueError("Data is corrupted.")

        try:
            password_encrypted_wrapper = decrypt(
                pin_encrypted,
                pin,
                iter_count
            )
        except:
            raise WrongPin()
        password_encrypted_wrapper = json.loads(password_encrypted_wrapper)
        return password_encrypted_wrapper, iter_count

    @classmethod
    def password_decrypt(
            cls,
            encrypted_data: bytes,
            password: str,
            iter_count: int
            ) -> object:
        password: bytes = password.encode()
        encrypted_data = base64.b64decode(encrypted_data)

        try:
            data = decrypt(
                encrypted_data,
                password,
                iter_count
            )
        except:
            raise WrongPassword()
        data = json.loads(data)
        return data

    @classmethod
    def from_decrypt(
            cls,
            encrypted_data: bytes,
            pin: int,
            password: str
            ) -> "Data":
        password_encrypted_wrapper, iter_count = \
            cls.pin_decrypt(encrypted_data, pin)
        data = cls.password_decrypt(
            password_encrypted_wrapper["data"],
            password,
            iter_count
        )
        return cls(
            password_encrypted_wrapper["name"],
            password_encrypted_wrapper["description"],
            data,
            iter_count
        )


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
            pin: int,
            password: str | None = None,
            drop_duplicate: bool = True
            ) -> Generator[tuple[Path, Data], None, None]:
        checksums: list[bytes] = []
        for encrypted_file_path in self.store_dir.glob(".*"):
            if not encrypted_file_path.is_file():
                continue

            with open(encrypted_file_path, "rb") as f:
                encrypted_data = f.read()

            password_encrypted_wrapper, iter_count = \
                Data.pin_decrypt(encrypted_data, pin)

            checksum = encrypted_data[:32]
            if checksum in checksums and drop_duplicate:
                encrypted_file_path.unlink()
                continue
            else:
                checksums.append(checksum)

            if password_encrypted_wrapper["name"].startswith("dummy-") \
                    and len(password_encrypted_wrapper["name"]) == 42:
                continue

            if password is not None:
                data = Data.password_decrypt(
                    password_encrypted_wrapper["data"],
                    password,
                    iter_count
                )
            else:
                encrypted_data = Value(
                    password_encrypted_wrapper["data"],
                    masked=True
                )
                data = [
                    ("encrypted_data", encrypted_data),
                    ("iter_count", iter_count)
                ]

            data = Data(
                password_encrypted_wrapper["name"],
                password_encrypted_wrapper["description"],
                data,
                iter_count
            )
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
            pin: int,
            password: str,
            dummy_duplicates: int = 0
        ) -> Path:
        assert isinstance(data, Data)
        file_path = Path(f".{uuid.uuid4()}")
        data.encrypt_dump(file_path, pin, password)

        for _ in range(dummy_duplicates):
            dummy_data = self.create_dummy()
            dummy_file_path = Path(f".{uuid.uuid4()}")
            dummy_data.encrypt_dump(dummy_file_path, pin, password)

        return file_path

    def delete(self, file_path: Path):
        file_path.unlink()
