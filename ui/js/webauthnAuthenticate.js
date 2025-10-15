import { backendUrl } from "./const.js";
import { base64url } from "./rfc4648.js";

/**
 * This is an extension of webauthnAuthenticate.js keycloak 26.4
 * @see https://raw.githubusercontent.com/keycloak/keycloak/refs/tags/26.4.0/themes/src/main/resources/theme/base/login/resources/js/webauthnAuthenticate.js
 */
export class WebauthnAuthenticate {
    constructor() {
        console.log("Init WebauthnAuthenticate");
    }

    // singleton
    abortController = undefined;

    signal() {
        if (this.abortController) {
            // abort the previous call
            const abortError = new Error("Cancelling pending WebAuthn call");
            abortError.name = "AbortError";
            this.abortController.abort(abortError);
        }

        this.abortController = new AbortController();
        return this.abortController.signal;
    }

    async authenticateByWebAuthn(input) {
        // Check if WebAuthn is supported by this browser
        if (!window.PublicKeyCredential) {
            this.returnFailure(input.errmsg);
            return;
        }
        if (!input.isUserIdentified) {
            try {
                const result = await this.doAuthenticate([], input.challenge, input.userVerification, input.rpId, input.createTimeout, input.errmsg);
                this.returnSuccess(result, input.challenge, input.username);
            } catch (error) {
                this.returnFailure(error);
            }
            return;
        }
        this.checkAllowCredentials(input.challenge, input.userVerification, input.rpId, input.createTimeout, input.errmsg);
    }

    async checkAllowCredentials(challenge, userVerification, rpId, createTimeout, errmsg) {
        const allowCredentials = [];
        const authnUse = document.forms['authn_select'].authn_use_chk;
        if (authnUse !== undefined) {
            if (authnUse.length === undefined) {
                allowCredentials.push({
                    id: base64url.parse(authnUse.value, { loose: true }),
                    type: 'public-key',
                });
            } else {
                authnUse.forEach((entry) =>
                    allowCredentials.push({
                        id: base64url.parse(entry.value, { loose: true }),
                        type: 'public-key',
                    }));
            }
        }
        try {
            const result = await this.doAuthenticate(allowCredentials, challenge, userVerification, rpId, createTimeout, errmsg);
            this.returnSuccess(result, challenge);
        } catch (error) {
            this.returnFailure(error);
        }
    }

    doAuthenticate(allowCredentials, challenge, userVerification, rpId, createTimeout, errmsg) {
        // Check if WebAuthn is supported by this browser
        if (!window.PublicKeyCredential) {
            this.returnFailure(errmsg);
            return;
        }

        const publicKey = {
            rpId: rpId,
            challenge: base64url.parse(challenge, { loose: true })
        };

        if (createTimeout !== 0) {
            publicKey.timeout = createTimeout * 1000;
        }

        if (allowCredentials.length) {
            publicKey.allowCredentials = allowCredentials;
        }

        if (userVerification !== 'not specified') {
            publicKey.userVerification = userVerification;
        }

        return navigator.credentials.get({
            publicKey,
            signal: this.signal()
        });
    }

    returnSuccess(result, challenge, username) {
        console.log("WebauthnAuthenticate result: ", result);
        const payload = {
            clientDataJSON: base64url.stringify(new Uint8Array(result.response.clientDataJSON), { pad: false }),
            authenticatorData: base64url.stringify(new Uint8Array(result.response.authenticatorData), { pad: false }),
            signature: base64url.stringify(new Uint8Array(result.response.signature), { pad: false }),
            credentialId: result.id,
            challenge,
            username
        }

        if (result.response.userHandle) {
            payload.userHandle = base64url.stringify(new Uint8Array(result.response.userHandle), { pad: false });
        }

        fetch(`${backendUrl}/users/authenticate`, {
            method: "POST",
            body: JSON.stringify(payload),
            headers: {
                accept:"application/json",
                "content-type": "application/json"
            }
        }).then(res => {
            if(!res.ok) throw new Error("Authentication failed");
            res.json().then((data) => {
                console.log(data);
                document.getElementById("debug").innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word; max-width: 90%;">${JSON.stringify(data, null, 2)}</pre>`;
            }).catch(err => {
                console.log(err);
                document.getElementById("debug").innerHTML = err;
            });
        }).catch(err => {
            console.log(err);
            document.getElementById("debug").innerHTML = err;
        });

    }

    returnFailure(err) {
        console.log("WebauthnAuthenticate error: ", err);
        document.getElementById("debug").innerHTML = err;
    }
}


