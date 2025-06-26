# mda_mailchannels
an opensmtpd mda that works with MailChannels!

create a .build_env with your api key and dkim selector, or set them in in your
environment. they'll be built into the executable until my work use case for
this can deploy config through env vars and we can read it at runtime

```sh
# add variables one line each, NAME=VALUE
MDA_MAILCHANNELS_API_KEY=api-key-value-here
MDA_MAILCHANNELS_DKIM_SELECTOR=cool-dkim-selector
```

the .build_env file is read by a cargo build script
