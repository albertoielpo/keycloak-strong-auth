import fs from "fs";

/**
 * Load existing conf
 * @param {*} client 
 * @param {*} persistFile 
 * @returns 
 */
export async function setupVirtualAuthenticator(client, persistFile = "./authenticator.json") {
    await client.send("WebAuthn.enable");

    // Load saved credentials
    let saved = null;
    if (fs.existsSync(persistFile)) {
        saved = JSON.parse(fs.readFileSync(persistFile, "utf-8"));
        console.log("credentials loaded");
    }

    const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "usb",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
        },
    });

    console.log("Virtual authenticator created:", authenticatorId);

    if (saved?.credentials?.credentials?.length) {
        for (const cred of saved.credentials.credentials) {
            console.log("adding", cred);
            await client.send("WebAuthn.addCredential", {
                authenticatorId,
                credential: cred,
            });
        }
        console.log(`Restored ${saved.credentials.credentials.length} credential(s)`);
    }

    return {
        authenticatorId,
        async saveState() {
            console.log("Saving credentials....");
            const creds = await client.send("WebAuthn.getCredentials", { authenticatorId });
            console.log("creds", creds);
            fs.writeFileSync(persistFile, JSON.stringify({ credentials: creds }, null, 2));
            console.log("Saved!");
        },
    };
}
