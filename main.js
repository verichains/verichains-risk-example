import hmacSHA512 from 'crypto-js/hmac-sha256.js';
import fetch from 'node-fetch';
import {v4} from "uuid";
import dotenv from "dotenv";

dotenv.config();

var appid = process.env.APP_ID;
var appSecret = process.env.APP_SECRET;

var timestamp = new Date().getTime();
var nonce = v4().replace(/-/g, '');
const body = {"address": "0x5db20fb9b382e77c47034796db2093aa767ed702", "chain_id": 56}

const msg = appid + ";" + timestamp + ";" + nonce + ";" +"POST;/api/v1/address-security;" + JSON.stringify(body);
var hash = hmacSHA512(msg, appSecret);
var signature = hash.toString();

(async function main() {
    console.log(await(await fetch("https://risk.verichains.xyz/api/v1/address-security", {
        body: JSON.stringify(body),
        headers: {
          "Content-Type": "application/json",
          "X-Signature-Appid": appid,
          "X-Signature-Nonce": nonce,
          "X-Signature-Signature": signature,
          "X-Signature-Timestamp": timestamp
        },
        method: "POST"
      })).json())
})()

