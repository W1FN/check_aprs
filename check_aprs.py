#!/usr/bin/env python3

import asyncio
import json

import requests
import aprs

from secrets import ICINGA_AUTH

APRSIS_HOST = "noam.aprs2.net"
ICINGA_HOST = "https://localhost:5665"


def get_callsigns():
    r = requests.get(
        ICINGA_HOST + "/v1/objects/hosts",
        params={"filter": "host.vars.aprs.callsign", "attrs": "vars"},
        auth=ICINGA_AUTH,
        verify=False,
    )

    return [host["attrs"]["vars"]["aprs"]["callsign"] for host in r.json()["results"]]


def submit_check(callsign, message, performance_data=None):
    data = {
        "type": "Service",
        "filter": f'service.name=="aprsis" && host.vars.aprs.callsign=="{callsign}"',
        "exit_status": 0,
        "plugin_output": f"OK: {message}",
        # "check_source": "example.localdomain",
    }

    if performance_data is not None:
        data["performance_data"] = performance_data

    r = requests.post(
        ICINGA_HOST + "/v1/actions/process-check-result",
        headers={"Accept": "application/json"},
        auth=ICINGA_AUTH,
        data=json.dumps(data),
        verify=False,
    )

    # TODO: better error handling
    if r.status_code != 200:
        print("Error:", r.text)


def handle_packet(packet):
    print(packet.info)
    match packet.info:
        case aprs.PositionReport(_position=position, comment=comment):
            print("POS:", position, comment)
            submit_check(packet.source, comment.decode("ascii"))
        case aprs.InformationField(
            comment=comment, data_type=aprs.DataType.STATION_CAPABILITIES
        ) if comment.startswith(b"IGATE,"):
            # IGate StatusBeacon, should be comma seperated "key=value" fields
            igate_stats = comment.decode("ascii").split(",")[1:]
            submit_check(packet.source, comment.decode("ascii"), igate_stats)
        case aprs.InformationField(comment=comment):
            print("INFO:", comment)
            submit_check(packet.source, comment.decode("ascii"))


async def main():
    callsigns = get_callsigns()
    if callsigns:
        print(f"Monitoring callsigns: {', '.join(callsigns)}")
    else:
        print("No calligns defined in Icinga!")
        return

    transport, protocol = await aprs.create_aprsis_connection(
        host=APRSIS_HOST,
        port=14580,
        user="KC1GDW",
        passcode="-1",  # use a real passcode for TX
        command=f"filter b/{'/'.join(callsigns)}",
    )

    async for packet in protocol.read():
        print(packet)
        handle_packet(packet)
        # submit_check(packet.source, packet.info)


if __name__ == "__main__":
    asyncio.run(main())
