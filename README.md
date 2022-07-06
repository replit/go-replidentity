# Repl Identity

Blog post on https://blog.replit.com coming soon!

Repl Identity stores a `REPL_IDENTITY` token in every Repl automatically. This
token is a signed [PASETO](https://paseto.io) that includes verifiable repl
identity data (such as the user in the repl, and the repl ID).

**WARNING: in their current form, these tokens are very forwardable! You should
only send these tokens to repls that you trust, or between repls that you own.**

This package provides the necessary code to verify these tokens.

Check the example at `examples/extract.go` for an example usage. You can also
see this in action at https://replit.com/@mattiselin/repl-identity. If you are
logged in to Replit, you'll see your username when you click "Run" on the Cover
Page - that's Repl Identity at work.