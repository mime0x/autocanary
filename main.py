from pathlib import Path
from datetime import datetime, timezone
import json
import time
import requests
import pgpy


CONFIG_FILE = Path("config.json")
PRIVATE_KEY_FILE = Path("privatekey.asc")
CANARY_FILE = Path("canary.asc.txt")


def create_config():
    print(
        "[*] First time run detected.\n"
        "[*] Upload your PGP private key to this folder as "
        "'privatekey.asc'."
    )

    config = {
        "serviceName": input("[+] Name of your service: ")
    }

    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    print("\n[+] Configuration saved")


def load_config():
    if not CONFIG_FILE.exists():
        create_config()

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)

    except json.JSONDecodeError:
        print("[!] config.json invalid")

        create_config()

        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)

def get_bitcoin_hash():
    response = requests.get(
        "https://mempool.space/api/blocks/tip/hash",
        timeout=10
    )

    response.raise_for_status()

    return response.text.strip()


def create_canary(config, private_key):
    current_time = datetime.now(timezone.utc)

    signing_date_time = current_time.strftime(
        "%d %B %Y %H:%M:%S UTC"
    )

    recent_block_hash = get_bitcoin_hash()

    canary = f"""
LIBERTY CANARY

{config["serviceName"]} is in 100% control of all of its hardware, and the service is operating
normally.

{config["serviceName"]} is not under duress of any government or organization.

~!~

WARRANT CANARY

- As of {signing_date_time}, {config["serviceName"]} has not received:

 * A gag order preventing the disclosure of a broad order for user metadata
 * A gag order preventing the disclosure of a broad order for user data
 * A gag order preventing the disclosure of a targeted order for user data
 * A gag order preventing the disclosure of a targeted order for user metadata

{config["serviceName"]} has never received a legal order enforceable in its jurisdiction for
user data.

{config["serviceName"]} has never received a legal order enforceable in its jurisdiction for
any broad class of users.

{config["serviceName"]} has never received a gag order preventing disclosure of any broad
order.

A gag order refers to any legal order enforceable in {config["serviceName"]}'s jurisdiction
preventing disclosure of:
 * A request or order for user information
 * A request or order for investigative assistance
 * A request or order for technical assistance
 * Any other request, order, demand, or information of any type

Failure to update this canary does not mean {config["serviceName"]} has received a gag order,
nor is not updating it or omitting anything an attempt to communicate anything
to anyone. This canary serves only to periodically confirm certain facts as
long as they are true.

~!~

The current datetime:
{signing_date_time}

The most recent bitcoin block hash:
{recent_block_hash}

Until further notice, THIS CANARY SHOULD BE UPDATED EVERY 72 HOURS. Under no
circumstances should we let this canary go 96 hours without an update unless a
PGP-signed message changes the schedule.
"""
    message = pgpy.PGPMessage.new(
        canary,
        cleartext=True
    )

    signature = private_key.sign(message)

    signed_message = (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n"
        "\n"
        + canary +
        "\n"
        "-----BEGIN PGP SIGNATURE-----\n"
        + str(signature).split(
            "-----BEGIN PGP SIGNATURE-----\n", 1
        )[1]
    )

    return str(signed_message)


def main():
    config = load_config()

    if not PRIVATE_KEY_FILE.exists():
        print(
            "[!] privatekey.asc not found."
        )
        return

    private_key, _ = pgpy.PGPKey.from_file(PRIVATE_KEY_FILE)

    while True:
        try:
            print("[*] Generating canary...")

            signed_canary = create_canary(
                config,
                private_key
            )

            with CANARY_FILE.open("w", encoding="utf-8") as file:
                file.write(signed_canary)

            print("[+] Canary updated successfully.")
            print("[*] Next update in 72 hours.")

        except Exception as e:
            print(f"[!] Failed to update canary: {e}")

        time.sleep(72 * 60 * 60)


if __name__ == "__main__":
    main()