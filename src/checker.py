# coding: utf-8
# Copyright 2017

"""Password analysis module."""

from argparse import ArgumentParser, Namespace
from base64 import a85encode
from getpass import getpass
from math import log2
from re import findall
from string import punctuation
from sys import stderr, stdout
from typing import Dict, Tuple


class Checker():

    """Verify password properties."""

    red: str = '{0}'
    blue: str = '{0}'
    green: str = '{0}'
    password: str

    SCALE_LENGTH: int = 37
    MAXIMUM_REPEAT_SYMBOL: int = 2
    MAXIMUM_COMPLEXITY_BIT: int = 128
    TOTAL_AMOUNT_NOT_ASCII: int = 256
    TOTAL_AMOUNT_FREE_SPACE: int = 2
    MINIMUM_PASSWORD_LENGTH: int = 9
    TOTAL_AMOUNT_DIGIT_ASCII: int = 10
    MAXIMUM_REPEAT_SYMBOL_SET: int = 1
    MINIMUM_LENGTH_SYMBOL_SET: int = 2
    TOTAL_AMOUNT_CHARACTER_ASCII: int = 32
    TOTAL_AMOUNT_LOWERCASE_ASCII: int = 26
    TOTAL_AMOUNT_UPPERCASE_ASCII: int = 26
    BIT_STR: str = "Bit"
    AMOUNT_STR: str = "Amount"
    STATUS_STR: str = "Status"
    FREE_SPACE_STR: str = "Free space"
    DESCRIPTION_STR: str = "Description"
    ASCII_NUMERAL_STR: str = "ASCII numeral"
    NORMAL_LENGTH_STR: str = "Normal length"
    UNICODE_CHARACTER_STR: str = "Unicode character"
    ASCII_UPPERCASE_LETTER_STR: str = "ASCII uppercase letter"
    ASCII_LOWERCASE_LETTER_STR: str = "ASCII lowercase letter"
    ASCII_SPECIAL_CHARACTER_STR: str = "ASCII special character"
    NO_MATCHING_SYMBOL_SETS_STR: str = "No matching symbol sets"
    NON_ASCII_UPPERCASE_LETTER_STR: str = "Non-ASCII uppercase letter"
    NON_ASCII_LOWERCASE_LETTER_STR: str = "Non-ASCII lowercase letter"
    NO_CONSECUTIVE_REPETITION_SYMBOLS_STR: str = \
        "No consecutive repetition symbols"
    NO_SUBSTANTIALLY_DOMINANT_SYMBOLS_STR: str = \
        "No substantially dominant symbols"
    SEPARATOR_STR: str = '—' * 53
    JUSTIFY_STR: str = "{2}".center(25)
    FIELD_WIDTH: int = 33
    POSITIVE_CHAR: str = 'O'
    NEGATIVE_CHAR: str = 'X'
    POSITIVE_FILL_CHAR: str = '+'
    NEGATIVE_FILL_CHAR: str = '-'
    HINT_TEXT: str = "Enter password"
    LABEL_TEXT: str = "The password should be easily remembered ;)"
    DESCRIPTION: str = "Password check for compliance\n"\
                       "with minimum security requirements."
    RESULT_TEMPLATE: str = ("\t{0}\n"
                            f"{SEPARATOR_STR}\n"
                            f" {{1}} | {JUSTIFY_STR} | {{3}}\n"
                            f"{SEPARATOR_STR}\n"
                            "   {05}    | {04} |   {06}\n"
                            "   {08}    | {07} |   {09}\n"
                            "   {11}    | {10} |   {12}\n"
                            "   {14}    | {13} |   {15}\n"
                            "   {17}    | {16} |   {18}\n"
                            "   {20}    | {19} |   {21}\n"
                            "   {23}    | {22} |   {24}\n"
                            "   {26}    | {25} |   {27}\n"
                            "   {29}    | {28} |   {30}\n"
                            f"{SEPARATOR_STR}\n"
                            "   {32}    | {31} |   {33}\n"
                            "   {35}    | {34} |   {36}\n"
                            "   {38}    | {37} |   {39}\n"
                            f"{SEPARATOR_STR}\n"
                            "  {40}   {41}   {42}\n")

    def bit_entropy(self, password_properties: Dict[str, int]) -> int:
        """Return the calculated bit entropy for a password."""
        total_amount_symbol: int = 0

        if password_properties["uppercase_ascii_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_UPPERCASE_ASCII
        if password_properties["lowercase_ascii_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_LOWERCASE_ASCII
        if password_properties["digit_ascii_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_DIGIT_ASCII
        if password_properties["character_ascii_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_CHARACTER_ASCII
        if password_properties["uppercase_not_ascii_amount"] \
                or password_properties["lowercase_not_ascii_amount"] \
                or password_properties["unicode_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_NOT_ASCII
        if password_properties["space_amount"]:
            total_amount_symbol += self.TOTAL_AMOUNT_FREE_SPACE

        logarithm: float = log2(total_amount_symbol + 0.1)
        return int(logarithm * password_properties["length_amount"])

    def password_properties(self) -> Dict[str, int]:
        """Return specific properties of a password."""
        password_properties: Dict[str, int] = {"lowercase_not_ascii_amount": 0,
                                               "unicode_amount": 0,
                                               "uppercase_not_ascii_amount": 0}

        password_properties["uppercase_ascii_amount"] = \
            len(findall(r"[A-Z]", self.password))
        password_properties["lowercase_ascii_amount"] = \
            len(findall(r"[a-z]", self.password))
        password_properties["digit_ascii_amount"] = \
            len(findall(r"[0-9]", self.password))
        password_properties["character_ascii_amount"] = \
            len(findall(rf"[{punctuation}]", self.password))

        for symbol in findall(rf"[^A-Za-z0-9{punctuation} \t]", self.password):
            if symbol.isupper():
                password_properties["uppercase_not_ascii_amount"] += 1
            elif symbol.islower():
                password_properties["lowercase_not_ascii_amount"] += 1
            else:
                password_properties["unicode_amount"] += 1

        password_properties["space_amount"] = \
            len(findall(r"[ \t]", self.password))
        password_properties["length_amount"] = len(self.password)
        password_properties["sequential_repetition_amount"] = \
            len(findall(r"(.)\1+", self.password))
        password_properties["substantial_dominance_amount"] = \
            sum(1 for symbol in set(self.password)
                if self.password.count(symbol) > self.MAXIMUM_REPEAT_SYMBOL)
        password_properties["symbol_set_amount"] = sum(
            1 for kit in {
                self.password[i:i + self.MINIMUM_LENGTH_SYMBOL_SET]
                for i in range(
                    len(self.password) - self.MINIMUM_LENGTH_SYMBOL_SET
                )
            }
            if self.password.count(kit) > self.MAXIMUM_REPEAT_SYMBOL_SET
        )
        password_properties["bit_entropy_amount"] = \
            self.bit_entropy(password_properties)

        return password_properties

    def password_properties_form(self) -> str:
        """Return completed print form."""
        password_properties: Dict[str, int] = self.password_properties()

        return self.RESULT_TEMPLATE.format(
            self.blue.format(self.LABEL_TEXT),
            self.STATUS_STR, self.DESCRIPTION_STR, self.AMOUNT_STR,
            self.ASCII_UPPERCASE_LETTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["uppercase_ascii_amount"]
            ),
            self.ASCII_LOWERCASE_LETTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["lowercase_ascii_amount"]
            ),
            self.ASCII_NUMERAL_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["digit_ascii_amount"]
            ),
            self.ASCII_SPECIAL_CHARACTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["character_ascii_amount"]
            ),
            self.NON_ASCII_UPPERCASE_LETTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["uppercase_not_ascii_amount"]
            ),
            self.NON_ASCII_LOWERCASE_LETTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["lowercase_not_ascii_amount"]
            ),
            self.FREE_SPACE_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["space_amount"]
            ),
            self.UNICODE_CHARACTER_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["unicode_amount"]
            ),
            self.NORMAL_LENGTH_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["length_amount"],
                minimum_value=self.MINIMUM_PASSWORD_LENGTH
            ),
            self.NO_CONSECUTIVE_REPETITION_SYMBOLS_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["sequential_repetition_amount"],
                status_reverse=True
            ),
            self.NO_SUBSTANTIALLY_DOMINANT_SYMBOLS_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["substantial_dominance_amount"],
                status_reverse=True
            ),
            self.NO_MATCHING_SYMBOL_SETS_STR.ljust(self.FIELD_WIDTH),
            *self.determine_status(
                password_properties["symbol_set_amount"],
                status_reverse=True
            ),
            self.BIT_STR,
            *self.determine_status(
                password_properties["bit_entropy_amount"],
                is_entropy=True
            )
        )

    def determine_status(self, password_property: int,
                         status_reverse: bool = False, minimum_value: int = 0,
                         is_entropy: bool = False) -> Tuple[str, int]:
        """Return property status."""
        status: str

        if is_entropy:
            bit_fill: float = password_property * self.SCALE_LENGTH \
                / self.MAXIMUM_COMPLEXITY_BIT
            bit_fill = int(bit_fill) if bit_fill < self.SCALE_LENGTH \
                else self.SCALE_LENGTH

            negative_fill: str = self.red.format(
                self.NEGATIVE_FILL_CHAR * (self.SCALE_LENGTH - bit_fill)
            )
            status = self.green.format(self.POSITIVE_FILL_CHAR * bit_fill) \
                + negative_fill
        elif password_property > minimum_value:
            status = self.red.format(self.NEGATIVE_CHAR) \
                if status_reverse else self.green.format(self.POSITIVE_CHAR)
        else:
            status = self.green.format(self.POSITIVE_CHAR) \
                if status_reverse else self.red.format(self.NEGATIVE_CHAR)

        return status, password_property

    def encode_ascii85(self):
        """Change password to encoded."""
        try:
            byte_password: bytes = self.password.encode()
            byte_password = a85encode(byte_password)
            self.password = byte_password.decode()
        except UnicodeError as error:
            stderr.write(f"{error}\n")
            self.password = ''


if __name__ == "__main__":
    parser: ArgumentParser = ArgumentParser(description=Checker.DESCRIPTION)
    parser.add_argument("-c", dest="colors", help="turn color design",
                        action="store_true")
    parser.add_argument("-e", dest="encode", help="ASCII85 encode",
                        action="store_true")
    parser.add_argument("-s", dest="shows", help="show password",
                        action="store_true")
    args: Namespace = parser.parse_args()

    checker: Checker = Checker()
    checker.password = input(f"{Checker.HINT_TEXT}: ") \
        if args.shows else getpass()

    if args.colors:
        checker.red = "\x1b[31;1m{0}\x1b[0m"
        checker.blue = "\x1b[34;1m{0}\x1b[0m"
        checker.green = "\x1b[32;1m{0}\x1b[0m"

    if args.encode:
        checker.encode_ascii85()
        if args.shows:
            stdout.write(f"ASCII85: {checker.password}\n")

    stdout.write(checker.password_properties_form())
