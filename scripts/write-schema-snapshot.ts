import { mkdir, writeFile } from "node:fs/promises";
import { z } from "zod";
import { sourceReconstructionPacketSchema } from "../src/schema.js";

await mkdir(new URL("../schema", import.meta.url), { recursive: true });
await writeFile(new URL("../schema/reconstruction-packet-2.1.0.schema.json", import.meta.url), `${JSON.stringify(z.toJSONSchema(sourceReconstructionPacketSchema), null, 2)}\n`, "utf8");
