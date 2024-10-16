# nemo

查询AdGuardHome日志，将解析的域名IP加入Wireguard Allowed IP。

Usage: wg-look [OPTIONS]

╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────
│ --add-cloudfront        --no-add-cloudfront                                If [on], Amazon Clooudfront edge public cidrs will be added to Wireguard allowed ips.           │
│                                                                            [default: add-cloudfront]                                                                       │
│ --add-cloudflare        --no-add-cloudflare                                If [on], Cloudflare public cidrs will be added to Wireguard allowed ips.                        │
│                                                                            [default: no-add-cloudflare]                                                                    │
│ --limit                                        INTEGER RANGE [0<=x<=1000]  Limit the number of AdGuard Home DNS query logs to fetch. [default: 100]                        │
│ --install-completion                                                       Install completion for the current shell.                                                       │
│ --show-completion                                                          Show completion for the current shell, to copy it or customize the installation.                │
│ --help                                                                     Show this message and exit.                                                                     │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────
