#!/usr/bin/env python3

import asyncio
import dataclasses
import json
from typing import Optional

import aiohttp
import aprs

from secrets import ICINGA_AUTH, ICINGA_FINGERPRINT

APRSIS_HOST = "noam.aprs2.net"
ICINGA_HOST = "https://localhost:5665"


@dataclasses.dataclass
class APRSListener:
    session: aiohttp.ClientSession

    async def get_callsigns(self):
        async with self.session.get(
            "/v1/objects/hosts",
            params={"filter": "host.vars.aprs.callsign", "attrs": "vars"},
        ) as r:
            return [
                host["attrs"]["vars"]["aprs"]["callsign"]
                for host in (await r.json())["results"]
            ]

    async def submit_check(self, callsign, message, performance_data=None):
        data = {
            "type": "Service",
            "filter": f'service.name=="aprsis" && host.vars.aprs.callsign=="{callsign}"',
            "exit_status": 0,
            "plugin_output": f"OK: {message}",
            "check_source": "APRSIS",
        }

        if performance_data is not None:
            data["performance_data"] = performance_data

        async with self.session.post(
            "/v1/actions/process-check-result",
            json=data,
        ) as r:
            # TODO: better error handling
            if r.status != 200:
                print("Error:", r.text)

    async def handle_packet(self, packet):
        print(packet.info)
        match packet.info:
            case aprs.PositionReport(_position=position, comment=comment):
                print("POS:", position, comment)
                await self.submit_check(packet.source, comment.decode("ascii"))

            case aprs.InformationField(
                comment=comment, data_type=aprs.DataType.TELEMETRY_DATA
            ) if comment.startswith(b"#"):
                seq, *analog, bits = comment[1:].decode("ascii").split(",")
                telem = [
                    f"telem_seq={seq}",
                    *[f"telem_analog{idx}={a}" for idx, a in enumerate(analog)],
                    f"telem_bits={bits}",
                ]
                print("TELEM:", telem)
                await self.submit_check(packet.source, comment.decode("ascii"), telem)

            case aprs.InformationField(
                comment=comment, data_type=aprs.DataType.STATION_CAPABILITIES
            ) if comment.startswith(b"IGATE,"):
                # IGate StatusBeacon, should be comma seperated "key=value" fields
                igate_stats = comment.decode("ascii").split(",")[1:]
                await self.submit_check(
                    packet.source, comment.decode("ascii"), igate_stats
                )

            case aprs.InformationField(comment=comment):
                print("INFO:", comment)
                await self.submit_check(packet.source, comment.decode("ascii"))

    async def run(self):
        callsigns = await self.get_callsigns()
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
            asyncio.create_task(self.handle_packet(packet))


async def main():
    async with aiohttp.ClientSession(
        base_url=ICINGA_HOST,
        auth=aiohttp.BasicAuth(*ICINGA_AUTH),
        connector=aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(ICINGA_FINGERPRINT)),
        headers={"Accept": "application/json"},
    ) as session:
        await APRSListener(session).run()


if __name__ == "__main__":
    asyncio.run(main())
