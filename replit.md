# Discord Account Manager

## Overview

The Discord Account Manager (DAM) is a web-based, full-stack application designed to manage multiple Discord accounts efficiently. Originally an Electron desktop app, it has been re-engineered as a multi-user web platform. DAM aims to streamline various Discord-related tasks, offering features like multi-account management, automated presence and activity updates, message sending, reaction management, and sophisticated server and DM interaction. The project focuses on providing isolated user dashboards, enhanced security for sensitive data, and anti-detection mechanisms to mimic human user behavior, making it a robust tool for Discord power users.

## User Preferences

I prefer detailed explanations.
I want iterative development.
Ask before making major changes.
I like functional programming.
I prefer simple language.
Do not make changes to the folder `Z`.
Do not make changes to the file `Y`.

## System Architecture

The application is built on a **full-stack architecture** with an Express.js backend serving both REST APIs and static frontend files (Vanilla JS, HTML/CSS with ES modules). `discord.js-selfbot-v13` is used for Discord integration, maintaining a live multi-client pool in server memory.

**Key Architectural Decisions & Features:**

*   **Multi-user Platform:** Supports username/password signup (bcrypt) and Discord OAuth. Each user has an isolated dashboard, with data stored under `data/users/<userId>/` using a scoped JsonStore. User sessions are managed via device "remember me" tokens.
*   **Security:** Tokens are encrypted at rest with AES-256-GCM. Proxies are also encrypted and masked in the UI.
*   **Data Storage:** A robust JSON storage layer (`lib/jsonStore.js`) provides atomic writes, file mutexing, debounced coalescing, in-memory caching, rolling backups, and automatic restore.
*   **Networking:** Per-account proxy support for all traffic (REST + WebSocket), including `http`, `https`, `socks`, `socks4`, `socks5`. Auto-reconnect on proxy changes.
*   **Anti-Detection & Automation:** All sends are humanized with `sendTyping` and jittered delays. Message deletion uses a worker pool with global cooldowns.
*   **UI/UX Design:**
    *   Bilingual (English/Arabic) support with full RTL.
    *   Inline Lucide-style SVG icons for zero network requests.
    *   Lightweight CSS-only snowfall background.
    *   Unified UX feedback with toasts, pulse buttons, confirmation dialogs, and shake animations.
    *   Themed select components portal popovers to `<body>` to prevent clipping.
    *   Softened dark theme palette and refined low-volume sine-only sound effects.
    *   Global custom radios and checkboxes.
*   **Core Managers:**
    *   **TokensManager:** Multi-account hub for presence, bio, avatar, status rotation, and activity simulation. Supports "Apply to ALL connected" actions.
    *   **MessagesManager:** Send messages to channels, DMs, or groups, with repeat and schedule options.
    *   **ReactionManager:** Auto-react and auto-click buttons.
    *   **PrivateManager:** Real-time chat-style DM viewer with multi-account support, unread badges, and live updates via SSE. Includes bots-only filter and search.
    *   **StatsManager:** Analytics dashboard for accounts, servers, DMs, and groups.
    *   **LookupManager:** Server lookup by ID with comprehensive guild details.
    *   **TrueStudioManager:** TOTP-based Discord Developer Portal automation for creating teams, bot applications, and linking bots.
    *   **VoiceManager:** Comprehensive voice channel control, including join/leave, state presets, auto state cycling, and room rotation.
    *   **MassFriendManager:** Bulk add/remove friends with filters and rate-limiting.
*   **Search Functionality:** Enhanced global search in PrivateManager covering username, displayName, ID, and message content (cached + Discord's native search API).
*   **Cloning:** Advanced server cloning capabilities, including structure, channel permissions, and message restoration via webhooks.
*   **Background Tasks:** A system for managing single tasks per account with live SSE updates and a ring-buffer history.
*   **Deployment:** VM deployment is used due to persistent in-memory state of Discord clients.

## External Dependencies

*   **Express.js:** Web application framework for the backend.
*   **`discord.js-selfbot-v13`:** Discord API wrapper for self-botting functionalities.
*   **bcrypt:** For hashing user passwords.
*   **AES-256-GCM:** Encryption standard for sensitive data (tokens, proxy URLs).
*   **`helmet`:** For securing Express apps by setting various HTTP headers.
*   **`express-rate-limit`:** Middleware for limiting repeated requests to public APIs.
*   **`api.ipify.org`:** Used for testing egress IP in proxy functionality.
*   **RFC 6238 TOTP:** Standard for Time-based One-Time Passwords, used in TrueStudioManager.