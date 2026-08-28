import { mkdir, writeFile } from "node:fs/promises";
import { z } from "zod";
import { sourceReconstructionPacketSchema } from "../src/schema.js";
import { projectStateReconstructionPacketSchema } from "../src/project-state.js";

await mkdir(new URL("../schema", import.meta.url), { recursive: true });
await writeFile(new URL("../schema/reconstruction-packet-2.2.0.schema.json", import.meta.url), `${JSON.stringify(z.toJSONSchema(sourceReconstructionPacketSchema), null, 2)}\n`, "utf8");
await writeFile(new URL("../schema/project-state-reconstruction-1.1.0.schema.json", import.meta.url), `${JSON.stringify(z.toJSONSchema(projectStateReconstructionPacketSchema), null, 2)}\n`, "utf8");
