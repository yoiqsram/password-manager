import tkinter
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
    COMMAND_ADD = "add"
    COMMAND_LIST = "list"
    COMMAND_SHOW = "show"
    COMMANDS = [
        COMMAND_ADD,
        COMMAND_LIST
    ]

    def __init__(self, store_dir: Path = Path(".")) -> None:
        self.manager = DataManager(store_dir.resolve())

    @classmethod
    def get_pin(self) -> int:
        pin = getpass("Enter your 6 pin numbers: ")
        if len(pin) != 6:
            raise ValueError("Invalid length of pin.")
        pin = int(pin.lstrip("0"))
        return pin

    @classmethod
    def get_password(self) -> str:
        password = getpass("Enter your master password: ")
        print()
        return password

    def add(
            self,
            name: str,
            description: str = "",
            generate_password: bool = False,
            dummy: int = 0,
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
        self.manager.add(data, pin, password, dummy)

    def list(self, **kwargs):
        pin = self.get_pin()
        for _, data in self.manager.iter(pin):
            print("-", data.name)

    def show(
            self,
            name: str,
            replace: bool = False,
            unsafe_show_password: bool = False,
            **kwargs
            ):
        pin = self.get_pin()
        for original_path, data in self.manager.iter(pin):
            if data.name != name:
                continue

            password = self.get_password()

            decrypted_data = Data.password_decrypt(
                data.data["encrypted_data"].value,
                password,
                data.data["iter_count"].value
            )
            data = Data.from_dict({
                "name": data.name,
                "description": data.description,
                "data": decrypted_data
            })

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
                self.manager.add(data, pin, password)
                original_path.unlink()

            return

        print(f"There's no data with name '{name}'.")
        raise SystemExit(1)
