# st2-GitHubWebhook


### v0.0.3 Changes

- Changed payload schema to match actual payload
- Forced utf8 encoding of secret - newer ST2 versions read secret as unicode, which HMAC doesn't like
- removed leftover copypasta code from `remove_trigger()`
