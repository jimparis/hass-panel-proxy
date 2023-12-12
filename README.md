# Panel Proxy

This Home Assistant component creates a panel that performs a reverse
proxy to any specified URL, with websockets support.  For example,
this allows you to add a sidebar entry that embeds an ESPHome
dashboard.

This similar to the built-in `proxy_iframe`, except instead of having
the client web browser directly access the resource, Home Assistant
will request the resource on your behalf and return it to the browser,
which avoids the need for additional SSL termination, authentication,
or VPN setup in order to access internal resources.

## Security

When you open the panel, this component will fetch a temporary
authentication token, then create an iframe with a URL that includes
this token.  When proxying requests, Home Assistant will check the
token before allowing access.

When the authentication token expires, a new token will be generated,
which will change the iframe URL and cause the target page to reload.
See `token_refresh` option to control this expiration.

## Usage

Put this folder in your `custom_components` directory.

Add configuration to `configuration.yaml`:

```
panel_proxy:
  esphome:
    title: 'ESPHome Dashboard'
    icon: mdi:chip
    url: 'http://esphome:6052/'
    require_admin: true
```
Supported options:

| Option          | Description                                             | Default        |
|-----------------|---------------------------------------------------------|----------------|
| `title`         | Title to display in sidebar                             |                |
| `icon`          | Icon to display in sidebar                              | `mdi:bookmark` |
| `url`           | The target URL, to which to proxy requests              |                |
| `token_refresh` | How many seconds each authentication token is valid for | 3600           |
| `verify_ssl`    | If `false`, skip SSL verification when accessing `url`  | `true`         |
| `require_admin` | Whether to make available to administrators only        | `false`        |

## Caveats

This rewrites absolute URLs in HTTP headers, like Apache's
`ProxyPassReverse` feature, but we don't rewrite URLs inside HTML.
This means that pages that expect to be able to use absolute paths
will fail.

## Inspiration

- Initial idea from https://github.com/doudz/homeassistant-panel_proxy
- Websockets support based on https://github.com/home-assistant/core/blob/dev/homeassistant/components/hassio/ingress.py
