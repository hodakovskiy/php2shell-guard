=== PHP2Shell Guard ===
Contributors: Hodakovskiy
Tags: security, malware, backdoor, monitoring, alerts
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Finds signs of a PHP2Shell compromise and warns you immediately by email, Slack/Discord webhook or Telegram. Read-only: it never changes or deletes your files.

== Description ==

PHP2Shell Guard answers two questions: "was this site broken into?" and "will I hear about it the moment it happens?"

**Scans (daily by default, or on demand)**

* PHP version, judged against the fixed releases (8.2.35, 8.3.36, 8.4.27, 8.5.12). This is the PHP that actually serves your site, not the command-line PHP.
* `session.upload_progress.enabled` (the CVE-2026-115560 mitigation), read from the live PHP configuration.
* WordPress core files against the official wordpress.org checksums, including unknown extra files in `wp-admin` and `wp-includes`.
* Plugin files against wordpress.org checksums, including modified, missing and added files.
* PHP files and handler-changing `.htaccess` / `.user.ini` inside `uploads`.
* PHP and config files changed since the first known exploitation date, with WordPress translation files recognised so they do not drown out real findings.
* `auto_prepend_file` / `auto_append_file` hooks (Wordfence's loader is recognised) and must-use plugins.
* Classic web-shell code patterns in `wp-content`.
* Administrators and new accounts, suspicious script or obfuscation content in options and posts, `siteurl` / `home` mismatches, and scheduled events with no code attached.
* Web server logs, when PHP can read them: bursts of 5xx responses and PHP worker crashes (segfaults), which is what failed exploitation attempts leave behind.

**Real-time alerts**

* A new administrator, by account creation or role change.
* A changed site URL, home URL or admin email; default role raised to administrator.
* An attempt to upload a PHP file.
* Every 15 minutes: changes to `wp-config.php`, `.htaccess`, `.user.ini`, `index.php`, must-use plugins and the active theme's `functions.php`, compared with a baseline. The watcher also catches an administrator inserted straight into the database, which bypasses WordPress hooks.
* A new PHP file in uploads.
* The guard being deactivated.
* Optional daily heartbeat, so silence tells you something is wrong.

Alerts go to email, a webhook (Slack-compatible, Discord or generic JSON) and Telegram. Repeats are de-duplicated and capped at 10 alerts an hour, so an attack cannot flood your inbox.

**It only reads.** It never edits, quarantines or deletes anything. You decide what to do with each finding, and can acknowledge it so it stops alerting.

== Installation ==

1. Upload the `php2shell-guard` folder to `/wp-content/plugins/` or install the zip from Plugins, Add New.
2. Activate it, open PHP2Shell Guard in the admin menu and click "Run full scan".
3. On the Alerts & settings tab, add an email, webhook or Telegram chat and press "Send a test alert".
4. Fix anything marked Critical. After a clean scan the plugin takes its baseline automatically; use "Accept current state" after later legitimate changes.

== Frequently Asked Questions ==

= Does it clean up the site? =

No. It finds and warns. Cleanup needs a human who understands how the site was entered; the plugin's admin page shows the maintainer's contact details if they are configured.

= Why did I get an alert for something I did myself? =

Creating an administrator or editing `wp-config.php` or `.htaccess` is exactly what an attacker does too, so the guard cannot tell the difference. Acknowledge the item, or click "Accept current state".

= Will a clean result prove the site is safe? =

No. It means no signs were found. An attacker who already runs code on the server can tamper with any plugin, including this one. Use the heartbeat, keep external backups and monitoring, and update PHP.

= My host sends no WordPress email =

Use the webhook or Telegram channel, which do not depend on the server's mail setup.

= Why are server logs not checked? =

Many hosts keep logs out of PHP's reach. Add log paths on the settings tab, or ask your host for the access logs.

= How do I translate it? =

Every text, including alerts, emails and the admin page, goes through WordPress's translation system (text domain `php2shell-guard`). Open `languages/php2shell-guard.pot` in Poedit or Loco Translate, save the result as `php2shell-guard-ru_RU.po` (use your locale code) and its compiled `.mo` next to it in `languages/`. The plugin picks it up when the site language matches. If the plugin is listed on wordpress.org, volunteers can also translate it at translate.wordpress.org without touching files.

= Do the timers work on low-traffic sites? =

They rely on WP-Cron. For reliable 15-minute watching, call `wp-cron.php` from a real cron job and set `DISABLE_WP_CRON` to true.

== Changelog ==

= 1.0.0 =
* First release. Fully translatable, with a .pot template included.
