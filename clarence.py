"""
A module for interacting with a password store using the `pass` command.

This module provides functions and classes to fetch and list secrets stored
in the password store managed by the `pass` command-line tool.

Functions:
    get_secret: Fetches a secret from the password store.
    list_secrets: Lists all the secrets in the password store.

Classes:
    Secret: Represents a secret as a string, obscured when printing.
    SecretsList: Represents a list of secrets.
"""

import subprocess


class Secret(str):
    """Represents a secret as a string, obscured when printing.

    This class inherits from `str` and overrides the string representation
    methods to obscure the secret when printed or represented.
    """

    def __new__(cls, value, *args, **kwargs):
        return super().__new__(cls, value, *args, **kwargs)

    def __init__(self, value):
        self._value = value

    def __str__(self):
        """Returns the obscured string representation of the secret.

        Returns:
            str: The obscured string representation of the secret.
        """
        return self._obscure()

    def __repr__(self):
        """Returns the obscured string representation of the secret
        for debugging.

        Returns:
            str: The obscured string representation of the secret.
        """
        return self._obscure()

    def __format__(self, format_spec):
        return self._obscure().__format__(format_spec)

    def _obscure(self):
        """Obscures the secret by replacing characters with asterisks.

        Returns:
            str: The obscured string.
        """
        length = len(self._value)
        if length <= 0:
            return "***"
        elif length < 5:
            return "*" * 5
        else:
            return self._value[0] + "*" * (length - 2) + self._value[-1]

    def reveal(self):
        """Reveal the secret.

        Returns:
            str: The unobscured secret as a string.
        """
        return self._value


def get_secret(path: str) -> Secret:
    """Fetches a secret from the password store.

    Args:
        path (str): The path to the secret in the password store.

    Returns:
        Secret: The retrieved secret as a `Secret` object.
    """
    result = subprocess.run(
        ["pass", "show", path], capture_output=True, text=True, check=True
    )
    return Secret(result.stdout.strip())


class SecretsList:
    """Represents a list of secrets."""

    def __init__(self, tree: str) -> None:
        """Initializes the SecretsList with a tree structure.

        Args:
            tree (str): The tree structure of secrets.
        """
        self.tree = tree

    def __str__(self) -> str:
        """Returns the string representation of the tree.

        Returns:
            str: The string representation of the tree.
        """
        return self.tree

    def __repr__(self) -> str:
        """Returns the string representation of the tree for debugging.

        Returns:
            str: The string representation of the tree.
        """
        return self.tree


def list_secrets() -> SecretsList:
    """Lists all the secrets in the password store.

    Returns:
        SecretsList: An object containing the list of secrets.
    """
    result = subprocess.run(
        ["pass"], capture_output=True, text=True, check=True
    )
    return SecretsList(result.stdout.strip())
