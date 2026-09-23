from src.deterministic.rules import detect_threats
from src.models.loader import load_architecture


def main() -> None:
    architecture = load_architecture("src/models/simple_web_api.json")

    threats = detect_threats(architecture)

    for threat in threats:
        print(threat)


if __name__ == "__main__":
    main()
