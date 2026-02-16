const fs = require("fs");

let PROXY_CONFIG;
let configContent = {};

const CONFIG_FILE_NAME = "mempool-frontend-config.json";

try {
  const rawConfig = fs.readFileSync(CONFIG_FILE_NAME);
  configContent = JSON.parse(rawConfig);
  console.log(`${CONFIG_FILE_NAME} file found, using provided config`);
} catch (e) {
  console.log(e);
  if (e.code !== "ENOENT") {
    throw new Error(e);
  } else {
    console.log(`${CONFIG_FILE_NAME} file not found, using default config`);
  }
}

const targetHost = configContent.NGINX_HOSTNAME || "litecoinspace.org";
const targetPort = configContent.NGINX_PORT ? `:${configContent.NGINX_PORT}` : "";
const targetProtocol = configContent.NGINX_PROTOCOL || "https";
const target = `${targetProtocol}://${targetHost}${targetPort}`;

PROXY_CONFIG = [
  {
    context: ["*", "/api/**", "!/api/v1/ws", "/testnet/api/**"],
    target,
    ws: true,
    secure: false,
    changeOrigin: true,
  },
  {
    context: ["/api/v1/ws"],
    target,
    ws: true,
    secure: false,
    changeOrigin: true,
  },
  {
    context: ["/resources/mining-pools/**"],
    target,
    secure: false,
    changeOrigin: true,
  },
  {
    context: [
      "/resources/assets.json",
      "/resources/assets.minimal.json",
      "/resources/worldmap.json",
    ],
    target,
    secure: false,
    changeOrigin: true,
  },
];

module.exports = PROXY_CONFIG;
