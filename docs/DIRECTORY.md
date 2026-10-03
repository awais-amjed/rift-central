# The public directories

How the server and bot directories are governed, and how they are moderated. Back to the [README](../README.md).

## The two directories

They look alike and are governed differently, which is the thing to know
before changing either.

A **server** listing reserves `(supabase_url, server_id)` — a pair that
exists whether or not its owner has claimed it. So the first account to
publish one holds the only slot, and a member of any server holds everything
needed to publish it. `publish_server` is therefore service-role only, behind
an edge function that redeems a one-time token against the server's own
domain. Domain control is the one thing central can actually verify.

A **bot** listing reserves nothing. It names no database central could ask,
points at no running thing, and two accounts listing a bot of the same name
are simply two rows. There is nothing an edge function could check, so
`publish_bot` is granted to `authenticated` and the uniqueness is per account
— the failure that rule avoids is an author permanently unable to list their
own work.

Ranking is a like rather than a rating. An average needs volume before it
means anything, and what a rating would really measure — does this bot work —
is invisible to a database that never touches the server the bot runs on.
Installs would be the better signal and cannot be counted: adding a bot is an
invite minted on the admin's own server, and central never hears about it.
`public_bots.like_count` is denormalised and recounted by trigger, because
the default browse order *is* that number and an `ORDER BY` over a subquery
cannot use an index.

## Moderating the directory

Everything else here is ciphertext and cannot be moderated, by design. The
directory is the exception — names, descriptions and icons written by
strangers — and it is served from the same address as accounts, DMs and
backups. So it has a report button and moderators.

- **Anyone signed in reports** a listing from the directory in the app, with
  a reason from a short list and optional words. One open report per person
  per listing, twenty a day.
- **Moderators work on the admin site** (on its own domain), never
  in the app. There they see each reported listing with its reports, what it
  said when reported, and who published it.
- **Hide** takes a listing out of everyone's browse, drops its icon (the
  nightly sweep deletes the bytes) and closes its reports. The owner still sees
  the listing and the reason, and republishing does not bring it back. A
  moderator can show it again.
- **Keep it up** closes the reports and leaves the listing.
- **Ban** stops an account publishing and hides everything it has listed.
  Lifting a ban restores publishing but not the listings; each comes back by
  hand.

**A moderator is a separate account, not a Rift account.** It is an auth user
with a password and no profile, listed in `central_admins`; a trigger stops a
Rift account becoming one and stops one claiming a handle. Every moderation
function also requires the session's second factor (`aal2`), so the admin site
makes a new moderator set up an authenticator app on first sign-in, and a
password alone reaches nothing.

**Five wrong codes lock the second factor for fifteen minutes**, the right
code included, and sign the account out everywhere. Supabase Auth's own limit
on code checks is per IP address (15 a minute, fixed), so a password and
enough addresses would otherwise make a six-digit code guessable in hours. The
count is per account, kept by `hook_mfa_verification_attempt` (002), which
Supabase Auth calls on every code. **The managed service offers that hook only
on its Team plan and above**, so on the hosted project the function exists and
is never called; on the self-hosted stack (`stack/`) it is on. Somebody holding
the password can keep the real moderator locked out — the answer to that is a
new password.

Adding or removing one, on the machine that runs central's stack:

```bash
./scripts/add_admin.sh moderator@example.com "Their name"   # asks for a password
./scripts/add_admin.sh --remove moderator@example.com
```

Use an address with no Rift account. The script reads the stack's secret key
from `stack/.env` and never takes the password as an argument.
