import shutil
import tkinter
import uuid
from data import Value, Data, DataManager
from getpass import getpass
from pathlib import Path


def copy_clipboard(text: str) -> None:
    root = tkinter.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


class App:
    NAME = "Sunday Mangler"
    DESCRIPTION = f"""{NAME} is a password manager application that allows you
    to store username and password safely to encrypted files.
    Encrypted files will be stored in the app directory with random UUID.
    Authentication require username and a pair of 6-PIN and password."""

    COMMAND_ADD = "add"
    COMMAND_ADD_HELP = """Add"""

    COMMAND_REMOVE = "rm"
    COMMAND_REMOVE_HELP = """Remove"""

    COMMAND_EDIT = "edit"
    COMMAND_EDIT_HELP = """Edit"""

    COMMAND_LIST = "list"
    COMMAND_LIST_HELP = """List"""

    COMMAND_SHOW = "show"
    COMMAND_SHOW_HELP = """Show"""

    COMMAND_REFRESH = "refresh"
    COMMAND_REFRESH_HELP = """Redo encryption on the encrypted data and dummy files.
    It is recommended to do it periodically to difficult decryption by strangers."""

    DEFAULT_DUMMY = 1
    DEFAULT_REPLACE = True

    def __init__(
            self,
            store_dir: Path = Path(".")
            ) -> None:
        self.manager = DataManager(store_dir.resolve())

    @classmethod
    def get_pin(self) -> int:
        pin = getpass("Enter your master 6-pin: ")
        if len(pin) != 6:
            raise ValueError("Invalid length of pin.")
        pin = int(pin.lstrip("0"))
        return pin

    @classmethod
    def get_password(self) -> str:
        password = getpass("Enter your master password: ")
        print()
        return password

    @staticmethod
    def generate_password() -> str:
        raise NotImplementedError()

    def add(
            self,
            username: str,
            name: str,
            description: str,
            generate_password: bool = False,
            dummy: int | None = None,
            **kwargs
            ) -> None:
        pin, password = self.get_pin(), self.get_password()

        print("=" * 50)
        data_username = input("Username: ")
        if generate_password:
            data_password = self.generate_password()
        else:
            data_password = getpass("Password: ")

        data = Data(
            name,
            description,
            [
                ("username", data_username),
                ("password", Value(data_password, masked=True))
            ]
        )

        if dummy is None:
            dummy = self.DEFAULT_DUMMY
        self.manager.add(data, username, pin, password, dummy)

    def remove(self, username: str, name: str, **kwargs):
        pin, password = self.get_pin(), self.get_password()
        for file_path, password_encrypted_data in \
                self.manager.iter(username, pin, name=name):
            Data.password_decrypt(password_encrypted_data, password)
            file_path.unlink()
            print("Password has been removed.")
            return

        print("Password not found.")

    def rm(self, username: str, name: str, **kwargs):
        return self.remove(username, name)

    def edit(self, username: str, name: str, **kwargs):
        pin = self.get_pin()
        for file_path, password_encrypted_data in \
                self.manager.iter(username, pin, name=name):
            password = self.get_password()
            data = Data.password_decrypt(
                password_encrypted_data,
                password
            )

            print("Enter to keep the current value.")
            data_name = input(f"App name ({data.name}): ") or data.name
            data_description = input("Description: ") or data.description
            data_username = input(f"Username ({data.data['username'].value}): ") or data.data["username"].value
            data_password = getpass("Password: ") or data.data["password"].value

            data = Data(
                data_name,
                data_description,
                [
                    ("username", data_username),
                    ("password", Value(data_password, masked=True))
                ]
            )
            self.manager.add(data, username, pin, password)
            file_path.unlink()
            print("Password saved.")
            return

        print("Password was not found.")

    def list(self, username: str, **kwargs):
        pin = self.get_pin()
        result_count = 0
        for _, password_encrypted_data in self.manager.iter(username, pin):
            print("-", password_encrypted_data.name)
            result_count += 1

        print(f"Found {result_count} result(s)")

    def show(
            self,
            username: str,
            name: str,
            replace: bool | None = None,
            unsafe_show_password: bool = False,
            **kwargs
            ):
        if replace is None:
            replace = self.DEFAULT_REPLACE

        pin = self.get_pin()
        for original_path, password_encrypted_data in \
                self.manager.iter(username, pin, name=name):
            password = self.get_password()
            data = Data.password_decrypt(
                password_encrypted_data,
                password
            )

            print("=" * 50)
            print("Name         :", data.name)
            print("Description  :", data.description)
            print("=" * 50)

            print("Username   :", data.data["username"].value)

            if unsafe_show_password:                
                print("Password   :", data.data["password"].value)
            else:
                print(
                    f"Password   : {'*' * len(data.data['password'].value)} ",
                    end=""
                )
                copy_clipboard(data.data["password"].value)
                print("(Copied to the clipboard)")

            if replace:
                self.manager.add(
                    data,
                    username,
                    pin,
                    password
                )
                original_path.unlink()

            return

        print(f"There's no data with name '{name}'.")
        raise SystemExit(1)

    def refresh(
            self,
            username: str,
            dummy: int | None = None,
            **kwargs
            ) -> None:
        if dummy is None:
            dummy = self.DEFAULT_DUMMY

        pin = self.get_pin()
        data_paths: list[Path] = []
        for file_path, data in self.manager.iter(username, pin, exclude_dummy=False):
            data: Data
            if self.manager.is_dummy(data.name):
                file_path.unlink()
                continue

            data_paths.append(file_path)

        if len(data_paths) == 0:
            print(f"No data was found.")
            return

        else:
            password = self.get_password()
            for file_path in data_paths:
                with open(file_path, "rb") as f:
                    data = Data.from_decrypt(f, username, pin, password)

                self.manager.add(data, username, pin, password, dummy)
                file_path.unlink()

        print(f"Succesfully redo encryption to all data.")
