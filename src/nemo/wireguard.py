#!/usr/bin/env python3

import ipaddress
import json
import shutil
import subprocess
from collections import defaultdict

import requests
import typer
from tld import get_fld
from typing_extensions import Annotated

PEER_IP = "10.20.30.1"
AGH_HOST = "198.181.39.60"
AGH_LOG_URL = f"http://{AGH_HOST}/control/querylog"
AGH_BASIC_AUTH = ("clavicula", "J*RmR#YeQ2b5ohSz&mqn")
WORK_DIR = "/Users/wyatt/utils/wireguard"
WG_INTERFACE = "wg0"
WG_CONF_PATH = f"/etc/wireguard/{WG_INTERFACE}.conf"
ORG_STRINGS = {
    "cloudflare": "Cloudflare",
    "cloudfront": "Cloudfront",
    "google": "Google",
    "other": "Others",
}
PUBLIC_IPS = {
    ORG_STRINGS["cloudflare"]: "https://api.cloudflare.com/client/v4/ips",
    ORG_STRINGS[
        "cloudfront"
    ]: "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
    ORG_STRINGS["google"]: "https://www.gstatic.com/ipranges/goog.json",
}
IPV4_CIDRS_PATH = f"{WORK_DIR}/public_ipv4_cidrs.json"
SITE_PATH = f"{WORK_DIR}/sites.json"
ALLOWED_IPS_PATH = f"{WORK_DIR}/allowed_ips.json"
TMP_WG_CONF_PATH = f"{WORK_DIR}/tmp_{WG_INTERFACE}.conf"
TIMEOUT = 10


app = typer.Typer()


@app.command()
def dnslog(
    key: Annotated[
        str,
        typer.Option(
            help="Keyword to search logs, all IPs in the result will be added to Wireguard allowed ips."
        ),
    ] = "",
    add_cloudfront: Annotated[
        bool,
        typer.Option(
            help="If [on], Amazon Clooudfront edge public cidrs will be added to Wireguard allowed ips."
        ),
    ] = True,
    add_cloudflare: Annotated[
        bool,
        typer.Option(
            help="If [on], Cloudflare public cidrs will be added to Wireguard allowed ips."
        ),
    ] = False,
    limit: Annotated[
        int,
        typer.Option(
            min=0,
            max=1000,
            help="Limit the number of AdGuard Home DNS query logs to fetch.",
        ),
    ] = 100,
):
    if key:
        is_forced = True
    else:
        is_forced = False

    public_cidrs = _get_public_ipv4_cidrs(
        local_path=IPV4_CIDRS_PATH, public_urls=PUBLIC_IPS
    )
    adh_log_result = _search_adh_log(
        agh_log_url=f"{AGH_LOG_URL}?search={key}&limit={limit}", agh_auth=AGH_BASIC_AUTH
    )
    collated_sites = _collate_sites(
        sites=adh_log_result, public_cidrs=public_cidrs, is_forced=is_forced
    )

    with open(SITE_PATH) as f:
        local_sites = json.load(f)
        switch_cloudfront = local_sites.pop("add_cloudfront", None) != add_cloudfront
        switch_cloudflare = local_sites.pop("add_cloudflare", None) != add_cloudflare

    merged_sites = _merge_sites(
        local_data=local_sites,
        adh_log_data=collated_sites,
        switch_cloudfront=switch_cloudfront,
        switch_cloudflare=switch_cloudflare,
    )

    if merged_sites.pop("updated", None):
        _write_sites(
            site_path=SITE_PATH,
            sites=merged_sites,
            add_cloudfront=add_cloudfront,
            add_cloudflare=add_cloudflare,
        )
        allowed_ips = _concat_allowed_ips(
            public_cidrs=public_cidrs,
            sites=merged_sites,
            add_cloudfront=add_cloudfront,
            add_cloudflare=add_cloudflare,
        )
        with open(ALLOWED_IPS_PATH) as f:
            wg_allowed_ips = json.load(f)
        if set(allowed_ips) ^ (set(wg_allowed_ips)):
            _write_wg_allowed_ips(
                wgconf_path=WG_CONF_PATH,
                tmp_wgconf_path=TMP_WG_CONF_PATH,
                allowed_ips_path=ALLOWED_IPS_PATH,
                allowed_ips=allowed_ips,
            )

            shutil.copy(TMP_WG_CONF_PATH, WG_CONF_PATH)
            subprocess.run(
                [
                    "/usr/local/bin/wg-quick",
                    "down",
                    WG_INTERFACE,
                ]
            )
            subprocess.run(
                [
                    "/usr/local/bin/wg-quick",
                    "up",
                    WG_INTERFACE,
                ]
            )
    else:
        print("No new ips from AdGuard Home DNS query logs.")


def _get_public_ipv4_cidrs(local_path: str, public_urls: dict) -> dict:
    try:
        online_ipv4_cidrs = {}
        for owner, url in public_urls.items():
            data = requests.get(url, timeout=TIMEOUT).json()
            if owner == ORG_STRINGS["cloudfront"]:
                online_ipv4_cidrs[owner] = _sort_cidrs(
                    data.get("CLOUDFRONT_GLOBAL_IP_LIST")
                )

            if owner == ORG_STRINGS["google"]:
                online_ipv4_cidrs[owner] = _sort_cidrs(
                    [
                        item.get("ipv4Prefix")
                        for item in data.get("prefixes")
                        if "ipv4Prefix" in item
                    ]
                )

            if owner == ORG_STRINGS["cloudflare"]:
                online_ipv4_cidrs[owner] = _sort_cidrs(
                    data.get("result").get("ipv4_cidrs")
                )
    except requests.RequestException as e:
        print("Get Public IPs Failed.")
        print(e)
    else:
        with open(local_path, "w") as f:
            json.dump(
                online_ipv4_cidrs,
                f,
                indent=4,
            )
    finally:
        with open(local_path) as f:
            return json.load(f)


def _get_cidr_by_ip(ip: str, cidr_list: list[str] | None) -> str | None:
    if cidr_list:
        for cidr in cidr_list:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                return cidr


def _search_adh_log(agh_log_url: str, agh_auth: tuple) -> dict:
    sites = defaultdict(set)
    try:
        res = requests.get(url=agh_log_url, auth=agh_auth, timeout=TIMEOUT)
        if res.ok:
            log_list = res.json().get("data", None)
            for log in log_list:
                question = log.get("question")
                if question and question.get("type") == "A":
                    if answers := log.get("answer"):
                        for ans in answers:
                            if ans.get("type") == "A":
                                sites[question.get("name")].add(ans.get("value"))
    except Exception as e:
        print(f"Fetch AdGuard Home DNS query log failed!\n{e}")
    return sites


def _collate_sites(
    sites: dict[str, set], public_cidrs: dict[str, list], is_forced: bool
) -> dict:
    cloudfront_edge_sites = defaultdict(set)
    cloudflare_cdn_sites = defaultdict(set)
    google_sites = defaultdict(set)
    other_sites = defaultdict(set)
    if is_forced:
        other_sites = sites
    else:
        for key, value in sites.items():
            for ip in value:
                if _get_cidr_by_ip(ip, public_cidrs.get(ORG_STRINGS["cloudfront"])):
                    cloudfront_edge_sites[key].add(ip)
                elif _get_cidr_by_ip(ip, public_cidrs.get(ORG_STRINGS["cloudflare"])):
                    cloudflare_cdn_sites[key].add(ip)
                elif _get_cidr_by_ip(ip, public_cidrs.get(ORG_STRINGS["google"])):
                    google_sites[key].add(ip)
                else:
                    other_sites[key].add(ip)

    return {
        ORG_STRINGS["cloudfront"]: cloudfront_edge_sites,
        ORG_STRINGS["cloudflare"]: cloudflare_cdn_sites,
        ORG_STRINGS["google"]: google_sites,
        ORG_STRINGS["other"]: other_sites,
    }


def _merge_sites(
    local_data: dict,
    adh_log_data: dict,
    switch_cloudfront: bool,
    switch_cloudflare: bool,
) -> dict:
    updated = switch_cloudfront | switch_cloudflare
    merged_data = {}

    merged_keys = set(local_data.keys())
    if new_keys := set(adh_log_data.keys()).difference(merged_keys):
        updated = True
        merged_keys.update(new_keys)

    for key in merged_keys:
        local_sites = local_data.get(key, {})
        adh_sites = adh_log_data.get(key, {})
        merged_sites = {}

        domains = set(local_sites.keys())
        if new_domains := set(adh_sites.keys()).difference(domains):
            updated = True
            domains.update(new_domains)

        for domain in domains:
            local_ips = set(local_sites.get(domain, ""))
            adh_ips = adh_sites.get(domain, set())

            if adh_ips.difference(local_ips):
                updated = True
                merged_sites[domain] = local_ips | adh_ips
            else:
                merged_sites[domain] = local_ips

        merged_data[key] = merged_sites
    return merged_data | {"updated": updated}


def _sort_cidrs(cidrs: list | set) -> list:
    return sorted(cidrs, key=lambda net: ipaddress.ip_network(net))


def _sort_ips(ips: list | set) -> list:
    return sorted(ips, key=lambda ip: ipaddress.ip_address(ip))


def _sort_sites(site_dict: dict) -> dict:
    sorted_by_tld = dict(
        sorted(
            site_dict.items(), key=lambda item: str(get_fld(item[0], fix_protocol=True))
        )
    )
    return {key: _sort_ips(value) for key, value in sorted_by_tld.items()}


def _concat_allowed_ips(
    public_cidrs: dict, sites: dict, add_cloudfront: bool, add_cloudflare: bool
) -> list:
    cloudfront_cidrs = public_cidrs.get(ORG_STRINGS["cloudfront"])
    google_cidrs = public_cidrs.get(ORG_STRINGS["google"])
    cloudflare_cidrs = public_cidrs.get(ORG_STRINGS["cloudflare"])
    cloudfront_edge_sites = sites.get(ORG_STRINGS["cloudfront"])
    google_sites = sites.get(ORG_STRINGS["google"])
    cloudflare_cdn_sites = sites.get(ORG_STRINGS["cloudflare"])
    other_sites = sites.get(ORG_STRINGS["other"])

    allowed_ips = [PEER_IP]

    if google_sites:
        allowed_google_cidrs = {
            _get_cidr_by_ip(ip, google_cidrs)
            for ip in set().union(*google_sites.values())
        }
        allowed_ips.extend(_sort_cidrs(allowed_google_cidrs))

    if add_cloudflare and cloudflare_cdn_sites:
        allowed_cloudflare_cidrs = {
            _get_cidr_by_ip(ip, cloudflare_cidrs)
            for ip in set().union(*cloudflare_cdn_sites.values())
        }
        allowed_ips.extend(_sort_cidrs(allowed_cloudflare_cidrs))

    if add_cloudfront and cloudfront_edge_sites:
        allowed_cloudfront_cidrs = {
            _get_cidr_by_ip(ip, cloudfront_cidrs)
            for ip in set().union(*cloudfront_edge_sites.values())
        }
        allowed_ips.extend(_sort_cidrs(allowed_cloudfront_cidrs))
    if other_sites:
        allowed_ips.extend(_sort_ips(set().union(*other_sites.values())))
    return allowed_ips


def _write_wg_allowed_ips(
    wgconf_path: str,
    tmp_wgconf_path: str,
    allowed_ips_path: str,
    allowed_ips: list,
):
    ip_str = ",".join(allowed_ips)
    with open(wgconf_path) as f0, open(tmp_wgconf_path, "w") as f1, open(
        allowed_ips_path, "w"
    ) as f2:
        for line in f0:
            if line.startswith("AllowedIPs"):
                f1.write(f"AllowedIPs = {ip_str}\n")
            else:
                f1.write(line)
        json.dump(
            allowed_ips,
            f2,
            indent=4,
        )


def _write_sites(
    site_path: str, sites: dict, add_cloudfront: bool, add_cloudflare: bool
):
    with open(site_path, "w") as f:
        json.dump(
            {key: _sort_sites(value) for key, value in sorted(sites.items())}
            | {"add_cloudfront": add_cloudfront}
            | {"add_cloudflare": add_cloudflare},
            f,
            indent=4,
        )


def main():
    app()


if __name__ == "__main__":
    app()
