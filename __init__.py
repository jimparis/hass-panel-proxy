"""Register an proxy front end panel."""

import logging

import re
import jwt
import aiohttp
import asyncio
import functools
import ipaddress
import multidict
import voluptuous as vol

from aiohttp import ClientTimeout, hdrs, web
from aiohttp.web_exceptions import HTTPBadGateway, HTTPBadRequest, HTTPUnauthorized

from homeassistant.auth import jwt_wrapper
from homeassistant.components import frontend
from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import UNDEFINED
from homeassistant.components.http import KEY_AUTHENTICATED, KEY_HASS_REFRESH_TOKEN_ID, KEY_HASS_USER, StaticPathConfig
from homeassistant.components.http.auth import DATA_SIGN_SECRET

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

INIT_HEADERS_FILTER = {
    hdrs.ORIGIN,
    hdrs.HOST,
    hdrs.CONTENT_LENGTH,
    hdrs.CONTENT_ENCODING,
    hdrs.TRANSFER_ENCODING,
    hdrs.ACCEPT_ENCODING,  # Avoid local compression, as we will compress at the border
    hdrs.SEC_WEBSOCKET_EXTENSIONS,
    hdrs.SEC_WEBSOCKET_PROTOCOL,
    hdrs.SEC_WEBSOCKET_VERSION,
    hdrs.SEC_WEBSOCKET_KEY,
}
RESPONSE_HEADERS_FILTER = {
    hdrs.TRANSFER_ENCODING,
    hdrs.CONTENT_LENGTH,
    hdrs.CONTENT_TYPE,
    hdrs.CONTENT_ENCODING,
}

MIN_COMPRESSED_SIZE = 128
MAX_SIMPLE_RESPONSE_SIZE = 4194000

DOMAIN = "panel_proxy"

CONF_TITLE = "title"
CONF_PANEL_TITLE = "panel_title"
CONF_TOKEN_REFRESH = "token_refresh"
CONF_ICON = "icon"
CONF_URL = "url"
CONF_VERIFY_SSL = "verify_ssl"
CONF_REQUIRE_ADMIN = "require_admin"

CONF_RELATIVE_URL_ERROR_MSG = "Invalid relative URL. Absolute path required."
CONF_RELATIVE_URL_REGEX = r"\A/"

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: cv.schema_with_slug_keys(
            vol.Schema(
                {
                    vol.Required(CONF_TITLE): cv.string,
                    vol.Optional(CONF_PANEL_TITLE): cv.string,
                    vol.Optional(CONF_TOKEN_REFRESH, default=3600): cv.positive_int,
                    vol.Optional(CONF_ICON, default="mdi:bookmark"): cv.icon,
                    vol.Required(CONF_URL): vol.Any(
                        vol.Match(
                            CONF_RELATIVE_URL_REGEX, msg=CONF_RELATIVE_URL_ERROR_MSG
                        ),
                        vol.Url()),
                    vol.Optional(CONF_VERIFY_SSL, default=True): cv.boolean,
                    vol.Optional(CONF_REQUIRE_ADMIN, default=False): cv.boolean,
                }
            )
        )
    },
    extra=vol.ALLOW_EXTRA,
)

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Initialize proxy panel"""

    # Register a URL so we can fetch our panel_proxy.js module
    await hass.http.async_register_static_paths([
        StaticPathConfig("/panel_proxy_files",
                         __path__[0] + "/static",
                         cache_headers=False)
    ])

    # Loop through each configured panel entry
    for path, info in config[DOMAIN].items():

        # This is the path of the panel view
        panel_path = "proxy_" + path

        # This is the path of the endpoint that actually performs the
        # proxy operation.
        proxy_endpoint = "/proxied_" + path

        # Register the proxy endpoint
        websession = async_get_clientsession(hass)
        hass.http.register_view(PanelProxy(
            hass=hass,
            proxy_endpoint=proxy_endpoint,
            target_url=info.get(CONF_URL),
            verify_ssl=info.get(CONF_VERIFY_SSL),
            websession=websession))

        # Register the panel
        try:
            config = {
                "_panel_custom": {
                    "name": "panel-proxy",
                    "embed_iframe": False,
                    "trust_external": False,
                    "module_url": "/panel_proxy_files/panel_proxy.js",
                },
                "proxy_endpoint": proxy_endpoint,
                "url": info.get(CONF_URL),
                "title": info.get(CONF_PANEL_TITLE),
                "token_refresh": info.get(CONF_TOKEN_REFRESH),
            }

            frontend.async_register_built_in_panel(
                hass,
                component_name="custom",
                sidebar_title=info.get(CONF_TITLE),
                sidebar_icon=info.get(CONF_ICON),
                frontend_url_path=panel_path,
                config=config,
                require_admin=info.get(CONF_REQUIRE_ADMIN),
            )
        except ValueError as err:
            _LOGGER.error(
                "Unable to register panel proxy %s: %s",
                info.get(CONF_TITLE, path),
                err,
            )

    return True

class PanelProxy(HomeAssistantView):
    """Proxy view.  This is an endpoint that checks authentication and
    proxies requests to the target URL."""

    requires_auth = False
    cors_allowed = False
    name = "panel_proxy"

    def __init__(self, hass, proxy_endpoint, target_url, verify_ssl, websession):
        """Initialize view"""
        self.hass = hass;
        self.proxy_endpoint = proxy_endpoint
        self.url = proxy_endpoint + r"/{token}/{requested_url:.*}"
        self.target_url = target_url
        if not self.target_url.endswith("/"):
            self.target_url += "/"
        self.verify_ssl = verify_ssl
        self._websession = websession
        _LOGGER.debug(f"initialized proxy from {self.url} to {self.target_url}")

    async def _handle(self, request, token, requested_url):
        """Handle request"""
        if not await self.async_validate_token(request, token):
            raise HTTPUnauthorized() from None

        try:
            # Websocket
            if _is_websocket(request):
                return await self._handle_websocket(request, requested_url)

            # Normal request
            return await self._handle_request(request, requested_url, token)

        except aiohttp.ClientError as err:
            _LOGGER.debug(f"Proxy error with URL {requested_url}: {err}")

        raise HTTPBadGateway() from None

    get = _handle
    post = _handle
    put = _handle
    delete = _handle
    patch = _handle
#    options = _handle

    async def _handle_websocket(self, request, requested_url):
        """Handle websocket request"""
        req_protocols: Iterable[str]
        if hdrs.SEC_WEBSOCKET_PROTOCOL in request.headers:
            req_protocols = [
                str(proto.strip())
                for proto in request.headers[hdrs.SEC_WEBSOCKET_PROTOCOL].split(",")
            ]
        else:
            req_protocols = ()

        ws_server = web.WebSocketResponse(
            protocols=req_protocols, autoclose=False, autoping=False
        )
        await ws_server.prepare(request)

        # Preparing
        url = self.target_url + requested_url
        source_header = _init_header(request)

        # Support GET query
        if request.query_string:
            url = url.with_query(request.query_string)

        _LOGGER.debug(f"websocket start, url {url} headers {source_header}")
        # Start proxy
        async with self._websession.ws_connect(
                url,
                headers=source_header,
                protocols=req_protocols,
                autoclose=False,
                autoping=False,
                ssl=None if self.verify_ssl else False,
        ) as ws_client:
            # Proxy requests
            await asyncio.wait(
                [
                    asyncio.create_task(_websocket_forward(ws_server, ws_client)),
                    asyncio.create_task(_websocket_forward(ws_client, ws_server)),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

        return ws_server

    def build_response_headers(self, headers, token):
        out = multidict.CIMultiDict()
        self.base_url = f"{self.proxy_endpoint}/{token}/"
        for key, value in headers.items():
            # Strip out headers that shouldn't be sent back to client
            if key in RESPONSE_HEADERS_FILTER:
                continue

            # Map URLs in headers, similar to Apache's ProxyPassReverse feature
            for n in [ "Location", "Content-Location" ]:
                if key.upper() == n.upper() and value.startswith("/"):
                    value = self.base_url + value[1:]
            if key.upper() == "Set-Cookie".upper():
                value = re.sub(r"; path=/", f"; path={self.base_url}", value)
            out.add(key, value)
        return out

    async def _handle_request(self, request, requested_url, token):
        """Handle normal HTTP request"""

        url = self.target_url + requested_url
        source_header = _init_header(request)

        async with self._websession.request(
                request.method,
                url,
                headers=source_header,
                params=request.query,
                allow_redirects=False,
                data=request.content if request.method != "GET" else None,
                timeout=ClientTimeout(total=None),
                skip_auto_headers={hdrs.CONTENT_TYPE},
                ssl=None if self.verify_ssl else False,
        ) as result:
            headers = self.build_response_headers(result.headers, token)
            content_length_int = 0
            content_length = result.headers.get(hdrs.CONTENT_LENGTH, UNDEFINED)
            # Avoid parsing content_type in simple cases for better performance
            if maybe_content_type := result.headers.get(hdrs.CONTENT_TYPE):
                content_type: str = (maybe_content_type.partition(";"))[0].strip()
            else:
                content_type = result.content_type
            # Simple request
            if result.status in (204, 304) or (
                content_length is not UNDEFINED
                and (content_length_int := int(content_length or 0))
                <= MAX_SIMPLE_RESPONSE_SIZE
            ):
                # Return Response
                body = await result.read()
                simple_response = web.Response(
                    headers=headers,
                    status=result.status,
                    content_type=content_type,
                    body=body,
                    zlib_executor_size=32768,
                )
                if content_length_int > MIN_COMPRESSED_SIZE and _should_compress(
                    content_type or simple_response.content_type
                ):
                    simple_response.enable_compression()
                await simple_response.prepare(request)
                return simple_response

            # Stream response
            response = web.StreamResponse(status=result.status, headers=headers)
            response.content_type = result.content_type

            try:
                if _should_compress(response.content_type):
                    response.enable_compression()
                await response.prepare(request)
                # In testing iter_chunked, iter_any, and iter_chunks:
                # iter_chunks was the best performing option since
                # it does not have to do as much re-assembly
                async for data, _ in result.content.iter_chunks():
                    await response.write(data)

            except (
                aiohttp.ClientError,
                aiohttp.ClientPayloadError,
                ConnectionResetError,
            ) as err:
                _LOGGER.debug("Stream error %s / %s: %s", token, path, err)

            return response

    async def async_validate_token(self, request: web.Request, token: str) -> bool:
        """Validate a signed path token"""
        if (secret := self.hass.data.get(DATA_SIGN_SECRET)) is None:
            return False

        try:
            claims = jwt_wrapper.verify_and_decode(
                token, secret, algorithms=["HS256"], options={"verify_iss": False}
            )
        except jwt.InvalidTokenError:
            return False

        if not request.path.startswith(claims["path"]):
            _LOGGER.error(f"path mismatch {request.path} vs {claims['path']}")
            return False

        refresh_token = self.hass.auth.async_get_refresh_token(claims["iss"])

        if refresh_token is None:
            return False

        request[KEY_HASS_USER] = refresh_token.user
        request[KEY_HASS_REFRESH_TOKEN_ID] = refresh_token.id
        request[KEY_AUTHENTICATED] = True
        return True

@functools.lru_cache(maxsize=32)
def _forwarded_for_header(forward_for: str | None, peer_name: str) -> str:
    """Create X-Forwarded-For header."""
    connected_ip = ipaddress.ip_address(peer_name)
    return f"{forward_for}, {connected_ip!s}" if forward_for else f"{connected_ip!s}"

def _init_header(request):
    """Create initial headers."""
    headers = {
        name: value
        for name, value in request.headers.items()
        if name not in INIT_HEADERS_FILTER
    }

    # Set X-Forwarded-For
    forward_for = request.headers.get(hdrs.X_FORWARDED_FOR)
    assert request.transport
    if (peername := request.transport.get_extra_info("peername")) is None:
        _LOGGER.debug("Can't set forward_for header, missing peername")
        raise HTTPBadRequest()

    headers[hdrs.X_FORWARDED_FOR] = _forwarded_for_header(forward_for, peername[0])

    # Set X-Forwarded-Host
    if not (forward_host := request.headers.get(hdrs.X_FORWARDED_HOST)):
        forward_host = request.host
    headers[hdrs.X_FORWARDED_HOST] = forward_host

    # Set X-Forwarded-Proto
    forward_proto = request.headers.get(hdrs.X_FORWARDED_PROTO)
    if not forward_proto:
        forward_proto = request.scheme
    headers[hdrs.X_FORWARDED_PROTO] = forward_proto

    return headers

def _is_websocket(request: web.Request) -> bool:
    """Return True if request is a websocket."""
    headers = request.headers
    return bool(
        "upgrade" in headers.get(hdrs.CONNECTION, "").lower()
        and headers.get(hdrs.UPGRADE, "").lower() == "websocket"
    )

def _should_compress(content_type: str) -> bool:
    """Return if we should compress a response."""
    if content_type.startswith("image/"):
        return "svg" in content_type
    return not content_type.startswith(("video/", "audio/", "font/"))

async def _websocket_forward(ws_from, ws_to):
    """Handle websocket message directly."""
    try:
        async for msg in ws_from:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await ws_to.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await ws_to.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.PING:
                await ws_to.ping()
            elif msg.type == aiohttp.WSMsgType.PONG:
                await ws_to.pong()
            elif ws_to.closed:
                await ws_to.close(code=ws_to.close_code, message=msg.extra)
    except RuntimeError:
        _LOGGER.debug("websocket runtime error")
    except ConnectionResetError:
        _LOGGER.debug("websocket connection reset")
