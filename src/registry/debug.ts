import { readFileSync } from "fs";

const rawData = readFileSync("data/empirical_study_results.json", "utf-8");
const results = JSON.parse(rawData);

console.log(`Total entries captured: ${results.length}`);

if (results.length > 0) {
  console.log("\n--- RAW JSON STRUCTURE OF FIRST SUCCESSFUL SCAN ---");
  const preview = JSON.stringify(results[0].scan, null, 2);
  console.log(preview.substring(0, 1000) + (preview.length > 1000 ? "\n...[TRUNCATED]" : ""));
}
