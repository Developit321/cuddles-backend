require("dotenv").config();
const mongoose = require("mongoose");
const {
  ensurePreEventCharacters,
  PRE_EVENT_CHARACTERS,
} = require("../services/preEventCharacterSeed");

const mongoUri =
  process.env.MONGO_URI ||
  "mongodb://cuddles:LNum9ZwrrcNDyl5c@ac-r0ymzab-shard-00-00.bdtblda.mongodb.net:27017,ac-r0ymzab-shard-00-01.bdtblda.mongodb.net:27017,ac-r0ymzab-shard-00-02.bdtblda.mongodb.net:27017/?ssl=true&replicaSet=atlas-ll9zih-shard-0&authSource=admin&retryWrites=true&w=majority";

async function main() {
  await mongoose.connect(mongoUri);
  await ensurePreEventCharacters();
  console.log(`Seeded ${PRE_EVENT_CHARACTERS.length} pre-event characters.`);
  await mongoose.disconnect();
}

main().catch((error) => {
  console.error("Failed to seed pre-event characters:", error);
  process.exit(1);
});
