// main.mjs
import puppeteer from "puppeteer";
import { setupVirtualAuthenticator } from "./webauthn.mjs";

/**
 * Browser simulation with ctap2/usb webauthn
 */
(async () => {
    const browser = await puppeteer.launch({
        headless: false,
        args: ["--window-size=1600,1000"],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1600, height: 1000 });

    const client = await page.createCDPSession();
    const webauthn = await setupVirtualAuthenticator(client);

    // uncomment this code to enable the interval to save credentials... 
    // it updates authentication.json with the local credentials in order to be consistent across reloaded
    // setInterval(async () => {
    //     console.log("saving polling...");
    //     await webauthn.saveState(); // still connected
    //     console.log("end");
    // }, 10_000);

    // keycloak realm account path
    // await page.goto("http://localhost:8080/realms/sa/account");
    
    // ui path
    await page.goto("http://localhost");

})();
