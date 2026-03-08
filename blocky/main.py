import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s: %(message)s",
)


def main() -> None:
    from blocky.ui.application import BlockyApplication
    app = BlockyApplication()
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
