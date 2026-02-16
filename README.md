# Litecoin Space

<br>

Litepool is the fully-featured mempool visualizer, explorer, and API service running at [litecoinspace.org](https://litecoinspace.org/).

It is an open-source project developed and operated for the benefit of the Litecoin community, with a focus on the emerging transaction fee market that is evolving Litecoin into a multi-layer ecosystem.

# Installation Methods

litepool can be self-hosted on a wide variety of your own hardware, ranging from a simple one-click installation on a Raspberry Pi full-node distro all the way to a robust production instance on a powerful FreeBSD server.

**Most people should use a one-click install method.** Other install methods are meant for developers and others with experience managing servers.

This is currently being worked on...

<!-- <a id="one-click-installation"></a>
## One-Click Installation

Mempool can be conveniently installed on the following full-node distros:
- [Umbrel](https://github.com/getumbrel/umbrel)
- [RaspiBlitz](https://github.com/rootzoll/raspiblitz)
- [RoninDojo](https://code.samourai.io/ronindojo/RoninDojo)
- [myNode](https://github.com/mynodebtc/mynode)
- [Start9](https://github.com/Start9Labs/embassy-os)

**We highly recommend you deploy your own Mempool instance this way.** No matter which option you pick, you'll be able to get your own fully-sovereign instance of Mempool up quickly without needing to fiddle with any settings. -->

## Advanced Installation Methods

Litepool can be installed in other ways too, but we only recommend doing so if you're a developer, have experience managing servers, or otherwise know what you're doing.

- See the [`docker/`](./docker/) directory for instructions on deploying Litepool with Docker.
- See the [`backend/`](./backend/) and [`frontend/`](./frontend/) directories for manual install instructions oriented for developers.
- See the [`production/`](./production/) directory for guidance on setting up a more serious Litepool instance designed for high performance at scale.

## Scripted Installation (Ubuntu 22.04)

This repository includes an interactive installer for a full stack deployment (catcoind + electrs + MariaDB + backend + frontend + nginx). It is designed for a clean Ubuntu 22.04 server. The script lives inside this repo and uses the local working tree.

### What you need

- A running `catcoind` binary on the server, or a path to it.
- A domain name that points to the server (optional, only required if you want HTTPS).
- If you plan to use Electrum, the electrs fork for your chain. For Catcoin, use: `https://github.com/zedcoinorg/electrs`.

### Install using the script

1. Make the script executable: `chmod +x ./install-catcoin-explorer.sh`
2. Run it as root from the repo root: `sudo ./install-catcoin-explorer.sh`

The script will ask for:
- Explorer hostname or IP
- MariaDB database name/user/password
- catcoind RPC credentials, ports, and datadir
- Electrum server parameters (electrs repo, ports, network name)
- Whether to enable HTTPS (Let’s Encrypt)

### If you skip a domain / HTTPS

You can run on HTTP and update the domain later. Edit these files:
- `frontend/mempool-frontend-config.json`
- `backend/mempool-config.json` (update `EXTERNAL_DATA_SERVER.MEMPOOL_API`)
- `/etc/nginx/sites-available/<YOUR_HOST>.conf`

Then rebuild and deploy frontend:
- `cd frontend && npm ci && npm run build`
- `rsync -av frontend/dist/mempool/browser/ /var/www/<YOUR_HOST>/`
- `rsync -av frontend/dist/mempool/browser/en-US/ /var/www/<YOUR_HOST>/`
- `systemctl reload nginx`

### Services installed by the script

- `catcoind.service`
- `electrs.service` (if enabled)
- `catcoin-mempool.service`
- `mariadb.service`
- `nginx.service`
