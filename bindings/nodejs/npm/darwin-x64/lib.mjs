import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
export default join(__dirname, "libsensor-darwin-amd64.dylib");
