# ⋰⋱ Starling (v0.0.6)

> The simplest way to run your own fediverse server: no database, no workers, no DevOps.

- Runs on shared hosting
- No MySQL or PostgreSQL required (uses SQLite)
- No background workers or cron jobs
- Deploy like a simple PHP app

Starling is a lightweight ActivityPub server built with PHP and SQLite, designed to run on shared hosting and low-resource environments. It is built for small, independent instances that want to stay simple: PHP, SQLite, a Mastodon-compatible API, and built-in web and admin interfaces.

Inspired by starling murmurations: decentralized, leaderless, and shaped by nearby connection.

An idea by Domingos Faria.

## Highlights

- ActivityPub federation for posts, follows, replies, likes, and boosts
- Mastodon-compatible API surface
- Built-in web client and admin panel
- SQLite storage for straightforward deployment
- No heavy external dependencies such as dedicated cron jobs or extra worker services
- Designed to run comfortably on typical shared hosting and small VPS hosts.

## Why Starling?

Starling aims to keep the fediverse approachable.

It favors a small stack, simple deployment, and practical compatibility over heavy infrastructure. The goal is not to be the biggest platform, but to make it easy to run a personal or community server that can still speak to the wider network without depending on a large service stack.

## Fediverse Compatibility

Starling speaks ActivityPub and can interact with platforms such as:

- Mastodon
- GoToSocial
- Misskey
- Pleroma
- PixelFed
- other ActivityPub-compatible servers

Tested clients so far include Ivory, Mastodon iOS, Elk, Phanpy, Fedicat, MastoBlaster, and IceCubes.

## What You Can Do

- publish posts and replies
- follow local and remote account's
- like, boost, bookmark, lists, and filter content
- use Mastodon-compatible clients and web apps
- manage an instance with admin tools for federation, relays, maintenance, and delivery queues

## Requirements

- PHP 8.2 or newer with SQLite support

Starling runs on a minimal PHP stack and is compatible with typical LAMP-style hosting environments (no MySQL required). This makes it suitable for shared hosting, low-cost hosting, small VPS, or personal instances.

## Quick Start

1. Copy the project to your server.
2. Open `https://yourdomain.tld//install` and complete the installer.
3. Open `https://yourdomain.tld//admin` for general settings and instance operation.

## Docker Installation (optional)

If you don't want to run the project on 'bare metal', you can use docker containers.

1. Copy the project to your server, in a sub-directory. `git clone https://github.com/dfaria-eu/Starling.git` will create a sub-directory called Starling.
2. In the parent directory above the project, create a compose.yaml file containing this:
```
services:
  starling:
    build: ./Starling
    container_name: starling
    ports:
      - "5081:80"
    volumes:
      - /home/you/docker_stuff/starling/Starling:/var/www/html
    restart: unless-stopped
```

3. Change the volume path to match your situation. In this example, starling is the parent and Starling is the project directory that `git clone` created.
4. Run `docker compose up --build -d`
5. Configure a reverse proxy to send traffic through to port 5081. Nginx or a Cloudflare tunnel, for example.
6. Open `https://yourdomain.tld/install` in your browser and complete the installer.
7. Open `https://yourdomain.tld/admin` for general settings and instance operation.

## Project Status

Starling is already usable and feature-rich, but it is still a compact project with an intentionally simple architecture.

It is best suited to small instances, experiments, and independent deployments that value simplicity over large-scale operational complexity.

## License

Starling is free software. You can use, copy, modify, and redistribute it under the terms of the GNU Affero General Public License v3.0 or later. Starling is an idea by [Domingos Faria](https://dfaria.eu).

If you build on Starling, please let me know about modifications, improvements, and new ideas via my fediverse contact: `@df@s.dfaria.eu`.
