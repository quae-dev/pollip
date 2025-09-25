# pollip

Python library for modifying Hollow Knight: Silksong save data.

## Installation

```shell
pip install git+https://github.com/quae-dev/pollip.git
```

## Usage

```python
import pollip

# Open in `read_only` mode to avoid overwriting the save file.
with pollip.open_save_file("user1.dat", read_only=True) as save:
    print(save["playerData"]["version"])

# Otherwise, the data will be written when exiting the context.
with pollip.open_save_file("user2.dat") as save:
    save["playerData"]["geo"] = 10_000
```

## License

BSD 3-Clause — see [LICENSE] for full text.

<!-- Links -->

[LICENSE]: https://github.com/quae-dev/pollip/blob/main/LICENSE
