import { InternalServerErrorException } from "@nestjs/common";
import CryptoUtils from "./crypto.utils";
describe("CryptoUtils", () => {
    describe("sha", () => {
        it("should return a valid sha1", () => {
            const expectedSha = "1e4e888ac66f8dd41e00c5a7ac36a32a9950d271";
            const res = CryptoUtils.sha1("ciao");
            expect(res).toHaveLength(40); // SHA-1 40 bytes length
            expect(res).toStrictEqual(expectedSha);
        });

        it("should return a valid sha256", () => {
            const expectedSha =
                "b133a0c0e9bee3be20163d2ad31d6248db292aa6dcb1ee087a2aa50e0fc75ae2";
            const res = CryptoUtils.sha256("ciao");
            expect(res).toHaveLength(64); // SHA-256 64 bytes length
            expect(res).toStrictEqual(expectedSha);
        });
    });

    describe("scrypt", () => {
        it("should return a valid scrypt", async () => {
            const input = "ciao";
            const res1 = await CryptoUtils.scryptHashPassword(input);
            expect(res1.indexOf(".")).not.toBe(-1); // scrypt contains "."

            const res2 = await CryptoUtils.scryptHashPassword(input);
            expect(res1).not.toStrictEqual(res2); // scrypt is salt generated
        });

        it("should compare correctly a hashed scrypt password with a supplied plaintext", async () => {
            const supplied = "ciao";
            const stored = await CryptoUtils.scryptHashPassword(supplied);
            const res = await CryptoUtils.scryptComparePassword(
                stored,
                supplied
            );
            expect(res).toBeTruthy();
        });

        it("should throw an error if supplied is null", async () => {
            const supplied = null as any;
            try {
                await CryptoUtils.scryptHashPassword(supplied);
                expect(true).toBe(false);
            } catch (error) {
                // an invalid supplied plaintext will throw an error
                expect(true).toBe(true);
            }
        });
    });

    describe("aes", () => {
        it("should encrypt using AES", () => {
            const input = "ciao";
            const res = CryptoUtils.encryptStringWithAES(input);
            expect(res).not.toStrictEqual(input); // input should be encrypted
            expect(res).toHaveProperty("cipher");
            expect(res).toHaveProperty("iv");
        });

        it("should decrypt using AES", () => {
            const input = "ciao";
            const encrypted = CryptoUtils.encryptStringWithAES(input);
            const decrypted = CryptoUtils.decryptStringWithAES(encrypted);
            expect(decrypted).toStrictEqual(input);
        });
    });

    describe("rsa", () => {
        it("should encrypt using private key", () => {
            // digital signature - server side
            const privateKey =
                "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQ1hRWVZaQ1JOYnRLdGIKOUdCVE55RVUrcjVKNkhhWmtjTDRpRGJiZ0VHeDczakhoS2lJdjRNQnYvM0t2eHZOdldmZTFvcm1FY3U2QVZaMgp5Q1ZLZk43RGFaMWNYNllzNlVJSnhTZFNCVTM0a0VWcUtLbTdlcmxUWjdVa2FRV2ZTMFBNbUE1UnJJa0VCUTl6CmJmWE1OVE9PRE9VMEQ2L1ZnT0tnTXZ0RmR6WWFRVThLbEd5RUVvdHdRR2NiYWtpRmIxdy9qdCtteTNwNlN4bVgKTWdZNzRMQW01M2t6NkNuVUFwOFhtemw1am02YkpwVlBmOXhXcHdmS0x5MWZ1Y1NIMGRDTEU4MmZSNVZyVnVobgpkdDJCNjNqbE5xMjhhaGRsTmRUMjR6WG5aY2dSOU9OdjZ6OVZ0TzFaNTZVZ3JEY1ducUNib2tYbDhrWjJoa3lCCnZWd0owT3lkQWdNQkFBRUNnZ0VBREs1ODVtdmxJRnQ3d1l3eDlsQXBPU2ZUeEFFV1RvWmkxVEVnZmxOWXpya2cKQklScUYvc01taDAxZzJYMkNCQXhFUVVtWktkSjBEalQvY1lHb0dIclVIRit0Tk85TEVkTFZ1UGRpZG94Z1IxaApnSWJUd2trR0dFalo3bWxTeEJvTW4yOEJSbFpEcjU5WC9nclNZTEoyTmRyOWJabkNHWkhDam9GdndWRi9Ld0M5ClFMRTZuQVhtOFNMVmdNOFRJNjZtVm5DTzllaHRLUVRrSUtBL2ttQjJkanRFTTM5aWd1d3ZxU21JV1cybTJLOHIKNVE1eW02aTl3MXFOUlhEa1FJRURkWjBwVWtKSDltamxoUlZaQVZ6WEN1MXQxN2JINmZlYS90TkZZZjFzN2ZCaQo5MzVkS2VDcE5nOFZhemhGMjR3aEhuRmZ0MkFkNi9RaHBzZ1EzZllGZ1FLQmdRQzlJMHorZ0c5VWh1WXl3MzFsCnlnbStXNFozWnhoVm0wQ2xFVFdLbTFRTlk0aGxXNWlIUDkvbjdXQnZ2TlFTbGhVTm9pVnQyc0ljMkwzZFhyNUsKTFREZ3VWeVRreERxWkkzZkFuMnZuSk82M1VtK0dKMEVVMGhJa3NudnhIK1N5cTlkbXZ4VGg3Um9Ecjl5am1rbwpjQ2t0Y2JoK3RFRFlNYnVvU3lFSE9HUHpnUUtCZ1FETXVmV2pndERjMUFCV2NNejhVanJobCtqa3p2NEx1aFM3CnFsZ0YzWUs3TnIyZmpreUpVd0ZkWjZaQ1FXcUF6MmhlczgwNHM5c1JUalk0RVkrT0Z2ZThTK1JtRVRlWjZFOTIKckFweXgrcXcvQ2EzNDJueXpuejBOVTlkNklmdjZZMklLcmFXS1VHdkovSFJCV3hlQTAwdFFJNWxiTmpHRTJkZApkWHc4VDMzWEhRS0JnQUZzK0xHYWFqeHEzK1ZXRCtYcWhmUkhZRllhRXRiaVdyUmowdEYrcGoyTG1JV2JFU1ZECjEvNDVqZGFKeDlkMEJpaWFKa29Uc2c3aG0xekYwQTFqRmRFNzFIVFFVUHBUVTdad29GM29nanlRV25QeVg0eWUKekJhdjlKRzRHM1lSelF5WmxIbFV0b2xxUXdzc0E2TG9aWWNRS21IYUhmc0ROUFRwekEvdjN1RUJBb0dBR3N5aApCaVdDdDlXY3NiUVVjVmRHVSsreDBmbnlzWkJMVklHcEFpT01FSHZLK004RTM5a1l6YVJhMUVPQjhKaTEvZWVsCmpxMmttTEJYVXFHaDNDVFBpenVZQzNCbmllTXFPOHVybG5qckZQMzlCNGRpZ0NGZHBBNHlkSVdTL2VuaDJCaFgKVEhMY0lWU21TQWxndFRIVGNZQUk0K2dLdkdzZjFkRWlVVGJLcjFVQ2dZQmc4L3NvaEtDT1dNODdjS3hTQlRodwplbWJCUkxJSUpKb0Y3SGFMK3l0UThCMGI2ZzF4eG5UZndaQVJuMXV5dHZXT2ppdEZXSDlyc1JjUFBDT0lHSzFYCklRSWRIQ29KVXBmQ3cwOWhDQmM3MlBDTExNazFudWVOTEJPSzZydXdCQ2dzRzNhQi9LU1ROajdwcS9OUmZIeGUKODFOT0hGRXMxTDJ6TTJhd0hQQloyZz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K";
            const encryptedTestData =
                "TYiqlTbfEzHl8EoXqSJK0YDdsQVJ+QrHRZbLDzb41vTRqHf6WvKQvcfwjDChCwcbeYems1srn4VrGuNSepHr2P6vgcNwUJxpP5Ma5uxczPIP7UqxuChED7Ik4LsvsIdUPi+8loS+t2i8mcdfhzcq+3NfFgUw5zAwpO2ROO+/6TeumXU59rRvbbVQ84nEWEvCDdcOiTy+SQJnhyZF0HvWVFx2K5zWEUj6m9mgDlrayOwC/0Vmk2xJS2+cD7m8V4eL4KSJrfwOpNy5s5nVzJMEDUKVxE9sXS11rG6s2JSR5xoaBqwh3p0qX8En5pS16GduiLha/3pOh+6nCai3Y+gFFQ==";
            const data = JSON.stringify({
                name: "alberto",
                active: true,
                value: 150
            });
            const encrypted = CryptoUtils.privateRsaEncrypt(privateKey, data);
            expect(encrypted).not.toStrictEqual(data);
            expect(encrypted).toStrictEqual(encryptedTestData);

            // repeat with buffer instead of base64 key.pem
            // simulate to read such key from file
            const bufferPrivateKey = Buffer.from(privateKey, "base64");
            const encrypted2 = CryptoUtils.privateRsaEncrypt(
                bufferPrivateKey,
                data
            );
            expect(encrypted2).not.toStrictEqual(data);
            expect(encrypted2).toStrictEqual(encryptedTestData);
        });

        it("should decrypt using public key", () => {
            // client side
            const publicKey =
                "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFsMEdGV1FrVFc3U3JXL1JnVXpjaApGUHErU2VoMm1aSEMrSWcyMjRCQnNlOTR4NFNvaUwrREFiLzl5cjhiemIxbjN0YUs1aEhMdWdGV2RzZ2xTbnplCncybWRYRittTE9sQ0NjVW5VZ1ZOK0pCRmFpaXB1M3E1VTJlMUpHa0ZuMHREekpnT1VheUpCQVVQYzIzMXpEVXoKamd6bE5BK3YxWURpb0RMN1JYYzJHa0ZQQ3BSc2hCS0xjRUJuRzJwSWhXOWNQNDdmcHN0NmVrc1pseklHTytDdwpKdWQ1TStncDFBS2ZGNXM1ZVk1dW15YVZUMy9jVnFjSHlpOHRYN25FaDlIUWl4UE5uMGVWYTFib1ozYmRnZXQ0CjVUYXR2R29YWlRYVTl1TTE1MlhJRWZUamIrcy9WYlR0V2VlbElLdzNGcDZnbTZKRjVmSkdkb1pNZ2IxY0NkRHMKblFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
            const encrypted =
                "TYiqlTbfEzHl8EoXqSJK0YDdsQVJ+QrHRZbLDzb41vTRqHf6WvKQvcfwjDChCwcbeYems1srn4VrGuNSepHr2P6vgcNwUJxpP5Ma5uxczPIP7UqxuChED7Ik4LsvsIdUPi+8loS+t2i8mcdfhzcq+3NfFgUw5zAwpO2ROO+/6TeumXU59rRvbbVQ84nEWEvCDdcOiTy+SQJnhyZF0HvWVFx2K5zWEUj6m9mgDlrayOwC/0Vmk2xJS2+cD7m8V4eL4KSJrfwOpNy5s5nVzJMEDUKVxE9sXS11rG6s2JSR5xoaBqwh3p0qX8En5pS16GduiLha/3pOh+6nCai3Y+gFFQ==";
            const data = JSON.stringify({
                name: "alberto",
                active: true,
                value: 150
            });
            const decrypted = CryptoUtils.publicRsaDecrypt(
                publicKey,
                encrypted
            );
            expect(decrypted).toStrictEqual(data);

            // repeat with buffer instead of base64 pub.pem
            // simulate to read such key from file
            const bufferPublicKey = Buffer.from(publicKey, "base64");
            const decrypted2 = CryptoUtils.publicRsaDecrypt(
                bufferPublicKey,
                encrypted
            );
            expect(decrypted2).toStrictEqual(data);
        });

        it("should throw error if payload data is too large", () => {
            // digital signature - server side
            const privateKey =
                "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQ1hRWVZaQ1JOYnRLdGIKOUdCVE55RVUrcjVKNkhhWmtjTDRpRGJiZ0VHeDczakhoS2lJdjRNQnYvM0t2eHZOdldmZTFvcm1FY3U2QVZaMgp5Q1ZLZk43RGFaMWNYNllzNlVJSnhTZFNCVTM0a0VWcUtLbTdlcmxUWjdVa2FRV2ZTMFBNbUE1UnJJa0VCUTl6CmJmWE1OVE9PRE9VMEQ2L1ZnT0tnTXZ0RmR6WWFRVThLbEd5RUVvdHdRR2NiYWtpRmIxdy9qdCtteTNwNlN4bVgKTWdZNzRMQW01M2t6NkNuVUFwOFhtemw1am02YkpwVlBmOXhXcHdmS0x5MWZ1Y1NIMGRDTEU4MmZSNVZyVnVobgpkdDJCNjNqbE5xMjhhaGRsTmRUMjR6WG5aY2dSOU9OdjZ6OVZ0TzFaNTZVZ3JEY1ducUNib2tYbDhrWjJoa3lCCnZWd0owT3lkQWdNQkFBRUNnZ0VBREs1ODVtdmxJRnQ3d1l3eDlsQXBPU2ZUeEFFV1RvWmkxVEVnZmxOWXpya2cKQklScUYvc01taDAxZzJYMkNCQXhFUVVtWktkSjBEalQvY1lHb0dIclVIRit0Tk85TEVkTFZ1UGRpZG94Z1IxaApnSWJUd2trR0dFalo3bWxTeEJvTW4yOEJSbFpEcjU5WC9nclNZTEoyTmRyOWJabkNHWkhDam9GdndWRi9Ld0M5ClFMRTZuQVhtOFNMVmdNOFRJNjZtVm5DTzllaHRLUVRrSUtBL2ttQjJkanRFTTM5aWd1d3ZxU21JV1cybTJLOHIKNVE1eW02aTl3MXFOUlhEa1FJRURkWjBwVWtKSDltamxoUlZaQVZ6WEN1MXQxN2JINmZlYS90TkZZZjFzN2ZCaQo5MzVkS2VDcE5nOFZhemhGMjR3aEhuRmZ0MkFkNi9RaHBzZ1EzZllGZ1FLQmdRQzlJMHorZ0c5VWh1WXl3MzFsCnlnbStXNFozWnhoVm0wQ2xFVFdLbTFRTlk0aGxXNWlIUDkvbjdXQnZ2TlFTbGhVTm9pVnQyc0ljMkwzZFhyNUsKTFREZ3VWeVRreERxWkkzZkFuMnZuSk82M1VtK0dKMEVVMGhJa3NudnhIK1N5cTlkbXZ4VGg3Um9Ecjl5am1rbwpjQ2t0Y2JoK3RFRFlNYnVvU3lFSE9HUHpnUUtCZ1FETXVmV2pndERjMUFCV2NNejhVanJobCtqa3p2NEx1aFM3CnFsZ0YzWUs3TnIyZmpreUpVd0ZkWjZaQ1FXcUF6MmhlczgwNHM5c1JUalk0RVkrT0Z2ZThTK1JtRVRlWjZFOTIKckFweXgrcXcvQ2EzNDJueXpuejBOVTlkNklmdjZZMklLcmFXS1VHdkovSFJCV3hlQTAwdFFJNWxiTmpHRTJkZApkWHc4VDMzWEhRS0JnQUZzK0xHYWFqeHEzK1ZXRCtYcWhmUkhZRllhRXRiaVdyUmowdEYrcGoyTG1JV2JFU1ZECjEvNDVqZGFKeDlkMEJpaWFKa29Uc2c3aG0xekYwQTFqRmRFNzFIVFFVUHBUVTdad29GM29nanlRV25QeVg0eWUKekJhdjlKRzRHM1lSelF5WmxIbFV0b2xxUXdzc0E2TG9aWWNRS21IYUhmc0ROUFRwekEvdjN1RUJBb0dBR3N5aApCaVdDdDlXY3NiUVVjVmRHVSsreDBmbnlzWkJMVklHcEFpT01FSHZLK004RTM5a1l6YVJhMUVPQjhKaTEvZWVsCmpxMmttTEJYVXFHaDNDVFBpenVZQzNCbmllTXFPOHVybG5qckZQMzlCNGRpZ0NGZHBBNHlkSVdTL2VuaDJCaFgKVEhMY0lWU21TQWxndFRIVGNZQUk0K2dLdkdzZjFkRWlVVGJLcjFVQ2dZQmc4L3NvaEtDT1dNODdjS3hTQlRodwplbWJCUkxJSUpKb0Y3SGFMK3l0UThCMGI2ZzF4eG5UZndaQVJuMXV5dHZXT2ppdEZXSDlyc1JjUFBDT0lHSzFYCklRSWRIQ29KVXBmQ3cwOWhDQmM3MlBDTExNazFudWVOTEJPSzZydXdCQ2dzRzNhQi9LU1ROajdwcS9OUmZIeGUKODFOT0hGRXMxTDJ6TTJhd0hQQloyZz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K";
            let data = "";
            for (let ii = 0; ii < 300; ii++) {
                data = `${data}${ii}`;
            }
            expect(() =>
                CryptoUtils.privateRsaEncrypt(privateKey, data)
            ).toThrow(InternalServerErrorException);
        });
    });
});
