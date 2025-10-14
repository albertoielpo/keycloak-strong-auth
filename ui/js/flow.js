import { backendUrl } from "./const.js";
import { WebauthnAuthenticate } from "./webauthnAuthenticate.js";
import { WebauthnRegister } from "./webauthnRegister.js";

const webauthnRegister = new WebauthnRegister();
const webauthnAuthenticate = new WebauthnAuthenticate();

const registerBtn = document.getElementById("register")
const authenticateBtn = document.getElementById("authenticate")

// Add event listener
registerBtn.addEventListener('click', (e) => register(e));
authenticateBtn.addEventListener('click', (e) => authenticate(e));

// Functions registration

function resetDebug() {
    document.getElementById("debug").innerHTML = "";
}

async function register(e) {
    resetDebug();
    const username = document.getElementById("username").value;
    console.log(`register pressed for username ${username}...`);
    if(!username){ 
        alert("Username is mandatory");
        return;
    }
    
    // 1. challenge type REGISTER
    const res = await fetch(`${backendUrl}/users/challenge?type=REGISTER&username=${username}`);
    if(!res.ok) {
        const errMsg = "Challenge register failed";
        alert(errMsg);
        throw new Error(errMsg);
    }
    const data = (await res.json()).data;

    // 2. prepare data with labels
    const input = { 
        "challenge": data.challenge, 
        "userid": data.userid, 
        "username": data.username, 
        "signatureAlgorithms": data.signatureAlgorithms || [], 
        "rpEntityName": data.rpEntityName, 
        "rpId": data.rpId, 
        "attestationConveyancePreference": data.attestationConveyancePreference, 
        "authenticatorAttachment": data.authenticatorAttachment, 
        "requireResidentKey": data.requireResidentKey, 
        "userVerificationRequirement": data.userVerificationRequirement, 
        "createTimeout": 0, 
        "excludeCredentialIds": data.excludeCredentialIds || "",
        "initLabel": "Passkey (Default Label)", 
        "initLabelPrompt": "Please input your registered passkey's label", 
        "errmsg": "WebAuthn is not supported by this browser. Try another one or contact your administrator." 
    }

    // 3. sign with webauthn and send data to the backend
    webauthnRegister.registerByWebAuthn(input);
}

async function authenticate() {
    resetDebug();
    const username = document.getElementById("username").value;
    console.log(`authenticate pressed for username ${username}...`);
    if(!username){ 
        alert("Username is mandatory");
        return;
    }
    
    // 1. challenge type AUTHENTICATE
    const res = await fetch(`${backendUrl}/users/challenge?type=AUTHENTICATE&username=${username}`);
    if(!res.ok) {
        const errMsg = "Challenge authenticate failed";
        alert(errMsg);
        throw new Error(errMsg);
    }
    const data = (await res.json()).data;
    

    // 2. prepare data with labels
    const input = {
        isUserIdentified: data.isUserIdentified || false,
        challenge: data.challenge,
        userVerification: data.userVerification,
        rpId: data.rpId,
        createTimeout: 0,
        username,
        errmsg: "WebAuthn is not supported by this browser. Try another one or contact your administrator."
    };

    // 3. sign with webauthn and send data to the backend
    webauthnAuthenticate.authenticateByWebAuthn(input)
}