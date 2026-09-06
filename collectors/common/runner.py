from collectors.common.sender import send_event


def send_events(events):
    results = []

    for event in events:
        payload = event.to_dict()

        try:
            response = send_event(payload)

            results.append({
                "success": True,
                "event": payload,
                "response": response,
            })

        except Exception as exc:
            results.append({
                "success": False,
                "event": payload,
                "error": str(exc),
            })

    return results