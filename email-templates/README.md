# Email templates

The account emails Supabase sends, styled to match joinrift.app instead of
GoTrue's defaults.

They live with central because central is what sends them, and they are
kept as files because they are the only part of Rift's design that renders
somewhere we do not control, so they need to be reviewable and diffable like
everything else.

**The self-hosted stack reads them from here.** `mail-templates` in
`stack/docker-compose.yml` serves this folder on the internal network and Auth
fetches each one as it sends, so a `git pull` and `./up.sh` is the whole
update. On the managed project they are pasted into the dashboard —
**Authentication → Emails → Templates** — or PATCHed onto the project config;
the table says which box each one goes in.

| File | Dashboard template | Config field (`/config/auth`) |
| --- | --- | --- |
| `confirm-signup.html` | Confirm signup | `mailer_templates_confirmation_content` |
| `reset-password.html` | Reset password | `mailer_templates_recovery_content` |
| `change-email.html` | Change email address | `mailer_templates_email_change_content` |
| `magic-link.html` | Magic link | `mailer_templates_magic_link_content` |
| `invite.html` | Invite user | `mailer_templates_invite_content` |
| `reauthentication.html` | Reauthentication | `mailer_templates_reauthentication_content` |
| `password-changed.html` | *(API only)* | `mailer_templates_password_changed_notification_content` |

`reset-password.html` carries a **code and no action link**, unlike most reset emails. Rift resets
the password inside the app, because the value GoTrue stores is derived from the typed password on
the device — a web page setting it directly would leave an account the client could never sign in
to again. A link would also have landed on `/email-confirmation/`, which says the email was
confirmed, which is not what happened.

Only three of these can fire today. Signup confirmation is the one that
matters; the password-changed notification is enabled and sends itself; email
change is reachable because `mailer_secure_email_change_enabled` is on. Magic
link, invite and reauthentication are unused — Rift signs in with a password —
and they are here so that turning one on later does not put an unstyled email
in front of somebody.

## Variables

Go template syntax, substituted by GoTrue. They must survive editing exactly
as written, spaces included.

- `{{ .ConfirmationURL }}` — the action link. Points at GoTrue's `/verify`,
  which consumes the token and then redirects to the address the client asked
  for. See `SupabaseConfig.emailConfirmationRedirect` in the Rift repo, and
  `/email-confirmation/` in `rift-website` for where it lands.
- `{{ .Token }}` — the numeric code, for reauthentication.
- `{{ .Email }}` — the account's address. In `change-email.html` this is the
  **old** one.
- `{{ .NewEmail }}` — the address being moved to.

## Why they are built the way they are

**Tables, inline styles, no external CSS.** Outlook renders with Word, which
ignores most of a stylesheet, and Gmail strips `<style>` outright in some
configurations. Anything that must be right is an attribute or an inline
style. The `<style>` block holds only progressive enhancement: the
`color-scheme` declaration and one width breakpoint.

**The mark is an image; the word beside it is text.** Most clients block
remote images by default, so nothing an auth email needs may depend on one —
branding that silently vanishes is exactly what a forgery looks like. So the
lockup is split: `https://joinrift.app/assets/img/email-mark.png` for the
mark — served by `rift-website`, where it lives — with an empty
`alt` because the word "Rift" is already the next cell, and plain text for
the word. Blocked, the email loses a 26px square and keeps its name. What
was there before was a flat gradient tile, which was never the logo — it just
looked like something that had failed to load.

The PNG is the same artwork as the website header's inline SVG, rendered at
78px for a 26px slot, in `rift-website`:

```
rsvg-convert -w 78 -h 78 -o assets/img/email-mark.png mark.svg
```

**It cannot be renamed or moved.** Every email already sitting in an inbox
addresses it by that URL, and Gmail proxies and
caches it on terms of its own — replace the artwork in place and expect both
versions to be live for a while.

**The panel fills the width; the text inside it does not.** A narrow column
leaves most of the message pane as empty background, which reads as an email
that failed to load rather than a deliberately small one. So the panel is
100% wide and the copy inside is capped at 520px — long centred lines are
what stop reading well, not the panel around them.

**The greys are lighter than the website's.** Gmail and Outlook both lift a dark
background a few shades before they paint on it, which quietly eats the
contrast a palette was chosen for. Body text, fine print and footer all sit a
step brighter here than the same roles do on the web.

**Dark, and declared as such.** `color-scheme: dark` tells Apple Mail and
Gmail not to run their own inversion over an email that is already dark, which
is what produces the grey-on-grey result otherwise. Every background is also
set as a `bgcolor` attribute, because Outlook ignores the CSS one.

**The button is drawn twice.** Word ignores `border-radius` and padding on an
anchor, so Outlook gets a VML rectangle and everything else gets the real
button. The two are inside complementary conditional comments; only one is
ever rendered.

**The fallback link says nothing and shows nothing.** An earlier version
printed the whole address as bare text, reasoning that scanners open every
link in a message and these tokens are single-use. Gmail linked it anyway, so
the exposure was there regardless and all the plain text bought was three
lines of unstyled blue through the middle of the email. It is now one muted
anchor with its colour set explicitly, so that no client decides to make it
blue either. The address itself is not printed: it is sixty characters of
token nobody reads, and the case this exists for is a client that dropped the
button's styling, where a plain link still works.

## Editing

There is no build step. Each file is standalone because each is pasted into a separate box, which means the shell —
everything outside the `<h1>` and the block under it — is duplicated seven
times. Change it in one and change it in all of them, or the set stops looking
like a set.

To preview, open the file in a browser. The `{{ … }}` placeholders render as
literal text and the button goes nowhere, which is enough to check the layout.
To check it in a real client, send one through the flow it belongs to rather
than trusting the browser: the browser is the one renderer that is guaranteed
to be permissive.
