# Clarence

A package for working with [`pass`](https://www.passwordstore.org/). It allows you to fetch and list secrets stored in the password store. It's named for an [excellent passer](https://en.wikipedia.org/wiki/Clarence_Seedorf).

## Installation

Before using Clarence please ensure you have the `pass` command-line tool installed and properly configured.

Then using the package is simply:

```sh
# If using uv
uv add clarence

# Or with pip
pip install clarence
```

## Usage

### Fetching a secret

To fetch a secret from your password store:

```python
from clarence import get_secret
secret = get_secret("path/to/secret")
```

The result of `get_secret` is an object of class `Secret`: this is basically just a regular `str` but with a print method that obscures the secret if you happen to print it to the console. While this helps make it harder to reveal a secret, you still must take care.

When you want to use your secret you need to use the `reveal` method. This makes it obvious when your code is using the unobscured secret.

```python
connection_string = f"mssql+pymssql://1234567:{secret.reveal()}@example.com/testingdb"
```

### Listing secrets

You can view all available secrets:

```python
from clarence import list_secrets
list_secrets()
```

The result is a `SecretsList` object, which will print in the same way as the `pass` command-line utility.

## Documentation

### Functions

#### `get_secret(path: str) -> Secret`

Fetches a secret from the password store.

- Args:
  - `path (str)`: The path to the secret in the password store.
- Returns:
  - `Secret`: The retrieved secret.

#### `list_secrets() -> SecretsList`

Lists all the secrets in the password store.

- Returns:
  - `SecretsList`: An object containing the list of secrets.

---

### Classes

#### `Secret`

Represents a secret as a string, obscured when printing.

- Methods:
  - `__init__(value: str)`: Initializes the secret with its actual value.
  - `__str__() -> str`: Returns an obscured string representation of the secret.
  - `__repr__() -> str`: Returns an obscured string representation for debugging.
  - `__format__(format_spec: str) -> str`: Returns the actual secret value when used in formatted strings.
  - `reveal() -> str`: Returns the actual secret value as a string.

#### `SecretsList`

Represents a list of secrets.

- Methods:
  - `__init__(tree: str)`: Initializes the SecretsList with a tree structure.
  - `__str__() -> str`: Returns the string representation of the tree.
  - `__repr__() -> str`: Returns the string representation of the tree for debugging.
