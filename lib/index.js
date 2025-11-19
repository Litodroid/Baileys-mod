import chalk from "chalk";
import makeWASocket from './Socket/index.js';
 
console.log(chalk.yellowBright.bold("\n📲 Lito-Mod\n"));
console.log(chalk.redBright.bold("\n✅IG:Litodroid  ✅Tiktok:Litodroid\n"));

export * from '../WAProto/index.js';
export * from './Utils/index.js';
export * from './Types/index.js';
export * from './Defaults/index.js';
export * from './WABinary/index.js';
export * from './WAM/index.js';
export * from './WAUSync/index.js';

export { makeWASocket };
export default makeWASocket;
