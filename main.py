import sys
sys.tracebacklimit = 0

from app import App
from argparse import ArgumentParser, Namespace, _SubParsersAction


def parse_command_add(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(
        App.COMMAND_ADD,
        help=App.COMMAND_ADD_HELP
    )
    parser.add_argument(
        "name",
        help=
            "Name is used to identify the data. "
            "It should be unique even though it will not test for the uniqueness. "
            "Otherwise it will randomly select data with similar names."
    )
    parser.add_argument(
        "--desc", "-D",
        dest="description",
        default="",
        help="Additional description of the data."
    )
    parser.add_argument(
        "--dummy",
        type=int,
        default=App.DEFAULT_DUMMY,
        help=
            "Number of encrypted dummy files to deceive the real on. "
            "It will be created by random order with the real one. "
            "More dummy files are more secure, but more time will be needed to extract the real one."
    )
    parser.add_argument(
        "--generate-password", "-G",
        action="store_true",
        help="Generate a new strong password, instead of providing one."
    )
    parser.add_argument(
        "--generate-password-length", "-L",
        type=int,
        default=16,
        help="Character length of the generated password."
    )


def parse_command_remove(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(
        App.COMMAND_REMOVE,
        help=App.COMMAND_REMOVE_HELP
    )
    parser.add_argument("name")


def parse_command_edit(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(
        App.COMMAND_EDIT,
        help=App.COMMAND_EDIT_HELP
    )
    parser.add_argument("name")


def parse_command_list(command_parser: _SubParsersAction) -> None:
    command_parser.add_parser(
        App.COMMAND_LIST,
        help=App.COMMAND_LIST_HELP
    )


def parse_command_show(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(
        App.COMMAND_SHOW,
        help=App.COMMAND_SHOW_HELP
    )
    parser.add_argument("name")
    parser.add_argument(
        "--replace", "-R",
        action="store_true",
        help=
            "Replace the stored encrypted file with the new one. "
            "Add more security by redoing encryption with new random salt."
    )
    parser.add_argument(
        "--unsafe-show-password",
        action="store_true",
        help=
            "Show password instead. "
            "By default, password will be copied to the clipboard while being masked on the result."
    )


def parse_command_refresh(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(
        App.COMMAND_REFRESH,
        help=App.COMMAND_REFRESH_HELP
    )
    parser.add_argument(
        "--dummy",
        type=int,
        default=App.DEFAULT_DUMMY,
        help="Number of dummy files along with the encrypted data files."
    )


def parse_args():
    parser = ArgumentParser(
        App.NAME,
        description=App.DESCRIPTION
    )
    parser.add_argument(
        "username",
        help="Username"
    )

    command_parser: _SubParsersAction = parser.add_subparsers(
        dest="command",
        required=True
    )
    parse_command_add(command_parser)
    parse_command_remove(command_parser)
    parse_command_edit(command_parser)
    parse_command_list(command_parser)
    parse_command_show(command_parser)
    parse_command_refresh(command_parser)

    return parser.parse_args()


def main(args: Namespace):
    app = App()
    command = getattr(app, args.command)
    command(**vars(args))


if __name__ == "__main__":
    args = parse_args()
    main(args)
