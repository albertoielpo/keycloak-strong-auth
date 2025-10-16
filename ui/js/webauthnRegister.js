import { backendUrl } from "./const.js";
import { base64url } from "./rfc4648.js";

/**
 * This is an extension of webauthnRegister.js keycloak 26.4
 * @see https://raw.githubusercontent.com/keycloak/keycloak/refs/tags/26.4.0/themes/src/main/resources/theme/base/login/resources/js/webauthnRegister.js
 */
export class WebauthnRegister {
    constructor() {
        console.log("Init WebauthnRegister");
    }

    async registerByWebAuthn(input) {

        // Check if WebAuthn is supported by this browser
        if (!window.PublicKeyCredential) {
            this.returnFailure(input.errmsg);
            return;
        }

        const publicKey = {
            challenge: base64url.parse(input.challenge, { loose: true }),
            rp: { id: input.rpId, name: input.rpEntityName },
            user: {
                id: base64url.parse(input.userid, { loose: true }),
                name: input.username,
                displayName: input.username
            },
            pubKeyCredParams: this.getPubKeyCredParams(input.signatureAlgorithms),
        };

        if (input.attestationConveyancePreference !== 'not specified') {
            publicKey.attestation = input.attestationConveyancePreference;
        }

        const authenticatorSelection = {};
        let isAuthenticatorSelectionSpecified = false;

        if (input.authenticatorAttachment !== 'not specified') {
            authenticatorSelection.authenticatorAttachment = input.authenticatorAttachment;
            isAuthenticatorSelectionSpecified = true;
        }

        if (input.requireResidentKey !== 'not specified') {
            if (input.requireResidentKey === 'Yes') {
                authenticatorSelection.requireResidentKey = true;
            } else {
                authenticatorSelection.requireResidentKey = false;
            }
            isAuthenticatorSelectionSpecified = true;
        }

        if (input.userVerificationRequirement !== 'not specified') {
            authenticatorSelection.userVerification = input.userVerificationRequirement;
            isAuthenticatorSelectionSpecified = true;
        }

        if (isAuthenticatorSelectionSpecified) {
            publicKey.authenticatorSelection = authenticatorSelection;
        }

        if (input.createTimeout !== 0) {
            publicKey.timeout = input.createTimeout * 1000;
        }

        const excludeCredentials = this.getExcludeCredentials(input.excludeCredentialIds);
        if (excludeCredentials.length > 0) {
            publicKey.excludeCredentials = excludeCredentials;
        }

        try {
            const result = await this.doRegister(publicKey);
            this.returnSuccess(result, input.initLabel, input.initLabelPrompt, input.username);
        } catch (error) {
            this.returnFailure(error);
        }
    }

    doRegister(publicKey) {
        return navigator.credentials.create({ publicKey });
    }


    getPubKeyCredParams(signatureAlgorithmsList) {
        const pubKeyCredParams = [];
        if (signatureAlgorithmsList.length === 0) {
            pubKeyCredParams.push({ type: "public-key", alg: -7 });
            return pubKeyCredParams;
        }

        for (const entry of signatureAlgorithmsList) {
            pubKeyCredParams.push({
                type: "public-key",
                alg: entry
            });
        }

        return pubKeyCredParams;
    }

    getExcludeCredentials(excludeCredentialIds) {
        const excludeCredentials = [];
        if (excludeCredentialIds === "") {
            return excludeCredentials;
        }

        for (const entry of excludeCredentialIds.split(',')) {
            excludeCredentials.push({
                type: "public-key",
                id: base64url.parse(entry, { loose: true })
            });
        }

        return excludeCredentials;
    }

    getTransportsAsString(transportsList) {
        if (!Array.isArray(transportsList)) {
            return "";
        }

        return transportsList.join();
    }

    returnSuccess(result, initLabel, initLabelPrompt, initUsername) {
        console.log("WebauthnRegister return success");

        const payload = {
            clientDataJSON: base64url.stringify(new Uint8Array(result.response.clientDataJSON), { pad: false }),
            attestationObject: base64url.stringify(new Uint8Array(result.response.attestationObject), { pad: false }),
            publicKeyCredentialId: base64url.stringify(new Uint8Array(result.rawId), { pad: false }),
            username: initUsername
        }

        if (typeof result.response.getTransports === "function") {
            const transports = result.response.getTransports();
            if (transports) {
                payload.transports = this.getTransportsAsString(transports);
            }
        } else {
            console.log("Your browser is not able to recognize supported transport media for the authenticator.");
        }

        let labelResult = window.prompt(initLabelPrompt, initLabel);
        if (labelResult === null) {
            labelResult = initLabel;
        }
        payload.authenticatorLabel = labelResult;

        fetch(`${backendUrl}/users/register`, {
            method: "POST",
            body: JSON.stringify(payload),
            headers: {
                accept:"application/json",
                "content-type": "application/json"
            }
        }).then(res => {
            if(!res.ok) throw new Error("Register failed");
            res.json().then((data) => {
                document.getElementById("debug").innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word; max-width: 90%;">${JSON.stringify(data, null, 2)}</pre>`;
            }).catch(err => {
                console.log(err);
                document.getElementById("debug").innerHTML = err;
            })
        }).catch(err => {
            console.log(err);
            document.getElementById("debug").innerHTML = err;
        });
    }

    returnFailure(err) {
        console.log("WebauthnRegister error: ", err);
        document.getElementById("debug").innerHTML = err;
    }
}







