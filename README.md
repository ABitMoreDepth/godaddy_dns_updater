# GoDaddy DNS Updater #
Primitive wrapper around GoDaddy's Domain Record API.  Retrieves the current externally facing IP address from one of a selection of services. Then attempts to update a user configurable Domain and record with the newly found IP address.

## Usage ##
1. Clone the repo,
2. Install project requirements, typically into a virtualEnv: `pip install -r requirements.txt`,
  - i.e. `mkvirtualenv --python=python3 -r requirements.txt`,
3. Run the module: `python -m GoDaddyDnsUpdater --help`,

In real life you'll want to provide a few options:
- `API_KEY`               Your GoDaddy API Key
- `API_SECRET`            Your GoDaddy API Secret
- `DOMAIN`                The target Domain to apply changes to, e.g. `facebook.com`
- `RECORD_TYPE`           The type of domain record we want to adjust, e.g. `A`, `TXT` etc.
- `RECORD_NAME`           The name of the record, e.g. `@` etc.

What this might look like:
`python -m GoDaddyDnsUpdater <API Key> <API Secret> <Domain> <Record Type> <Record Name> <--force> <--log-level info|warning etc.>`

The code won't push the record if the newly found IP address matches the current record's value.  This can be overridden with the `--force` option.

You can configure logging level with `--log-level`, and use one of `debug`, `info`, `warning`, `error`, or `none`.  Output is to stdOut by default.

### Credits ###
This module uses the following excellent libraries to make life just a little bit simpler, and will make it easier to cope with API changes in future..:
- [Cerberus](https://github.com/nicolaiarocci/cerberus)
- [IPGetter](https://github.com/phoemur/ipgetter)

I also make use of the excellent [Requests library](http://docs.python-requests.org/en/master/).

NOTE: I've only played with this on Python 3.5.x running on Ubuntu/Elementary OS & Raspbian, but to the best of my knowledge, it should work fine with 2.x as well on other OSes.
