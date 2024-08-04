import sys
sys.tracebacklimit = 0

from app import App
from argparse import ArgumentParser, Namespace, _SubParsersAction



def parse_command_add(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(App.COMMAND_ADD)
    parser.add_argument(
        "name",
        help="Name the new item."
    )
    parser.add_argument(
        "--desc", "-D",
        dest="description",
        default="",
        help="Description of the new item."
    )
    parser.add_argument(
        "--dummy",
        type=int,
        default=0,
        help="Number of encrypted dummy files created after create the real one."
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


def parse_command_list(command_parser: _SubParsersAction) -> None:
    command_parser.add_parser(App.COMMAND_LIST)


def parse_command_show(command_parser: _SubParsersAction) -> None:
    parser: ArgumentParser = command_parser.add_parser(App.COMMAND_SHOW)
    parser.add_argument("name")
    parser.add_argument(
        "--replace", "-R",
        action="store_true"
    )
    parser.add_argument(
        "--unsafe-show-password",
        action="store_true"
    )


def parse_args():
    parser = ArgumentParser("Password Manager")
    command_parser: _SubParsersAction = parser.add_subparsers(
        dest="command",
        required=True
    )

    parse_command_add(command_parser)
    parse_command_list(command_parser)
    parse_command_show(command_parser)

    return parser.parse_args()


def main(args: Namespace):
    app = App()
    command = getattr(app, args.command)
    command(**vars(args))


if __name__ == "__main__":
    args = parse_args()
    main(args)
