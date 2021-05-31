# Twitch Oauth2 Authentication Flow

This crate helps managing Twitch [OAuth authorization code
flow](https://dev.twitch.tv/docs/authentication/getting-tokens-oauth#oauth-authorization-code-flow)
to obtain a _user access token_. A user access token can be used by a
registered client to access APIs that require user impersonation, i.e.
information or operations that are only normally available to logged in users.
