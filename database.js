
import { MongoClient } from "mongodb";

const uri = process.env.MONGODB_URI;

if (!uri) {
  throw new Error("MONGODB_URI is missing from the .env file.");
}

const client = new MongoClient(uri);

let database;

export async function connectToDatabase() {
  await client.connect();

  database = client.db("zerotrace");
  await database.collection("users").createIndex(
  { email: 1 },
  { unique: true }
);
  await database.command({ ping: 1 });

  console.log("MongoDB connected successfully.");

  return database;
}

export function getDatabase() {
  if (!database) {
    throw new Error("MongoDB has not been connected yet.");
  }

  return database;
}
export function getUsersCollection() {
  return getDatabase().collection("users");
}