#!/usr/bin/env python3

import asyncio
import dataclasses

import aiohttp
import aprs
import asyncclick as click


@dataclasses.dataclass
class APRSListener:
    aprsis_host: str
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
                click.echo("Error:", r.text, err=True)

    async def handle_packet(self, packet):
        click.echo(packet.info)
        match packet.info:
            case aprs.PositionReport(_position=position, comment=comment):
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
                await self.submit_check(packet.source, comment.decode("ascii"))

    async def run(self):
        callsigns = await self.get_callsigns()
        if callsigns:
            click.echo(f"Monitoring callsigns: {', '.join(callsigns)}")
        else:
            click.echo("No calligns defined in Icinga!")
            return

        transport, protocol = await aprs.create_aprsis_connection(
            host=self.aprsis_host,
            port=14580,
            user="KC1GDW",
            passcode="-1",  # use a real passcode for TX
            command=f"filter b/{'/'.join(callsigns)}",
        )

        async for packet in protocol.read():
            click.echo(packet)
            asyncio.create_task(self.handle_packet(packet))


def validate_fingerprint(_ctx, _param, fingerprint: str):
    try:
        return bytes.fromhex(fingerprint.replace(":", ""))
    except ValueError:
        raise click.BadParameter("must be hexadecimal string (with or without colons)")


@click.command(context_settings={"max_content_width": 120})
@click.option(
    "--aprsis-host",
    envvar="APRSIS_HOST",
    help="APRSIS hostname",
    default="noam.aprs2.net",
    show_default=True,
)
@click.option(
    "--icinga-host",
    envvar="ICINGA_HOST",
    help="URL for Icinga2 API",
    default="https://localhost:5665",
    show_default=True,
)
@click.option(
    "--icinga-username",
    envvar="ICINGA_USERNAME",
    help="Username for Icinga2 API (env: ICINGA_USERNAME)",
    required=True,
)
@click.option(
    "--icinga-password",
    envvar="ICINGA_PASSWORD",
    help="Password for Icinga2 API (env: ICINGA_PASSWORD)",
    required=True,
)
@click.option(
    "--icinga-fingerprint",
    envvar="ICINGA_FINGERPRINT",
    help="SSL Certificate fingerprint for Icinga2 API (env: ICINGA_FINGERPRINT)",
    callback=validate_fingerprint,
    required=True,
)
async def main(
    icinga_host, icinga_username, icinga_password, icinga_fingerprint, aprsis_host
):
    "A passive Icinga monitoring daemon for APRS stations"

    async with aiohttp.ClientSession(
        base_url=icinga_host,
        auth=aiohttp.BasicAuth(icinga_username, icinga_password),
        connector=aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(icinga_fingerprint)),
        headers={"Accept": "application/json"},
    ) as session:
        await APRSListener(aprsis_host, session).run()


if __name__ == "__main__":
    main()
