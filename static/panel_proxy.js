import {
    LitElement,
    html,
    css,
    nothing,
} from "https://unpkg.com/lit-element@3.3.3/lit-element.js?module";

// This uses an iframe which pulls content from the internal proxying endpoint.
// This endpoint verifies authentication using a secure token that's embedded
// into the path.  This is so all subsequent requests from the proxied site
// will continue to include the token.

class PanelProxy extends LitElement {
    static get properties() {
        return {
            hass: { type: Object },
            narrow: { type: Boolean },
            route: { type: Object },
            panel: { type: Object },
            token: { type: String },
        };
    }

    // Grab a unique token
    getToken() {
        let refresh = this.panel.config.token_refresh;
        if (!refresh) {
            console.error("no refresh value");
            return;
        }
        this.hass.callWS({
            type: "auth/sign_path",
            path: this.panel.config.proxy_endpoint,
            expires: refresh,
        }).then((result) => {
            this.token = result.path.split("=").pop();
            // sign again before it expires
            clearTimeout(this.refreshTimer);
            this.refreshTimer = setTimeout(() => {
                this.getToken()
            }, (refresh * 0.95) * 1000);
        }, (error) => {
            // try again in 5 sec
            this.refreshTimer = setTimeout(() => {
                this.getToken()
            }, 5000);
        });
    }

    render() {
        if (this.token) {
            return html`
                <iframe
                   title="${this.panel.config.title ?? nothing}"
                   src="${this.panel.config.proxy_endpoint + "/" + this.token + "/"}"
                   sandbox="allow-forms allow-popups allow-pointer-lock allow-same-origin allow-scripts allow-modals allow-downloads"
                   allow="fullscreen"
                ></iframe>
            `;
        } else {
            // When this completes and changes this.token, Lit will re-render
            this.getToken();
            return html`
                <div>Authenticating...</div>
            `;
        }
    }

    static get styles() {
        return css`
            iframe {
                border: 0;
                width: 100%;
                height: 100%;
                background-color: var(--primary-background-color);
            }
            div {
                padding: 16px;
            }
        `;
    }
}
customElements.define("panel-proxy", PanelProxy);
