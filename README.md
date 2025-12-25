....bash
curl -sSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/moded-slowdns.py" | sed 's/\.unlink(missing_ok=True)/try: Path("\/etc\/resolv.conf").unlink()\nexcept FileNotFoundError: pass/g' | python3
