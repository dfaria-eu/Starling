# ⋰⋱ Starling 

Lightweight ActivityPub for small, independent servers.

Starling is a lightweight ActivityPub server written in PHP.

It is built for small, independent instances that want to stay simple: PHP, SQLite, a Mastodon-compatible API, and built-in web and admin interfaces.

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

## What You Can Do

- publish posts and replies
- follow local and remote account's
- like, boost, bookmark, lists, and filter content
- use Mastodon-compatible clients and web apps
- manage an instance with admin tools for federation, relays, maintenance, and delivery queues

## Requirements

- PHP 8.2 or newer with SQLite support

## Quick Start

1. Copy the project to your server.
2. Open `/install` and complete the installer.

## Project Status

Starling is already usable and feature-rich, but it is still a compact project with an intentionally simple architecture.

It is best suited to small instances, experiments, and independent deployments that value simplicity over large-scale operational complexity.

## License

Starling is free software. You can use, copy, modify, and redistribute it under the terms of the GNU Affero General Public License v3.0 or later. Starling is an idea by [Domingos Faria](https://dfaria.eu).

If you build on Starling, please let me know about modifications, improvements, and new ideas via my fediverse contact: `@df@s.dfaria.eu`.
