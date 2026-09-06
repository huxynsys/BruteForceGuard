from collectors.common.runner import send_events
from collectors.linux.ssh_auth_parser import parse_file


def main():
    events = parse_file(
        "collectors/sample_logs/auth.log"
    )

    results = send_events(events)

    for result in results:
        print(result)


if __name__ == "__main__":
    main()