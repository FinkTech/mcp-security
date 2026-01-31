import sqlite3 from "sqlite3";
import { promisify } from "util";

/**
 * Database tools for executing queries on development database
 *
 * 🚨 VULNERABILITIES:
 * - SEC-003: SQL Injection - queries not parameterized
 * - SEC-010: Insecure Communications - plaintext connection string
 * - SEC-012: Insecure Secrets Management - hardcoded credentials
 * - SEC-004: Information Disclosure - logs query results
 */

// 🚨 SEC-012: Hardcoded database credentials
// Should use secure secret management (Vault, AWS Secrets Manager, etc.)
const DB_CONFIG = {
  sqlite: "./dev-database.db",
  postgres: "postgresql://admin:SuperSecret123@localhost:5432/devdb",
  mysql: "mysql://root:password123@localhost:3306/development",
};

// 🚨 SEC-004: Logging database credentials
console.log("Database configuration:", DB_CONFIG);

// 🚨 SEC-010: Insecure Communications
// PostgreSQL and MySQL connection strings use unencrypted connections
// Should enforce SSL/TLS: sslmode=require for postgres, ssl: true for mysql

// ✅ FIX: Interface for database query result
interface DatabaseCountResult {
  count: number;
}

export async function databaseTools(query: string, database?: string) {
  console.log(`Executing database query on ${database || "default"}`);

  // 🚨 SEC-004: Information Disclosure
  // Logging the full query which may contain sensitive data
  console.log(`Query: ${query}`);

  try {
    // Default to SQLite for simplicity
    const dbType = database || "sqlite";

    if (dbType === "sqlite") {
      return await executeSQLite(query);
    } else {
      // For demo purposes, we'll just return a message for other DB types
      return {
        content: [
          {
            type: "text",
            text: `Would execute on ${dbType}:\n\n${query}\n\nConnection: ${DB_CONFIG[dbType as keyof typeof DB_CONFIG]}\n\n(PostgreSQL/MySQL not implemented in this demo, but would be vulnerable to same issues)`,
          },
        ],
      };
    }
  } catch (error: any) {
    // 🚨 SEC-009: Insecure Error Handling
    // Exposing full database errors including schema information
    console.error("Database query error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Database query failed:\n\nError: ${error.message}\n\nQuery: ${query}`,
        },
      ],
      isError: true,
    };
  }
}

async function executeSQLite(query: string) {
  // 🚨 SEC-003: CRITICAL - SQL Injection Vulnerability
  // Query is executed directly without parameterization
  // Attacker could input: "SELECT * FROM users; DROP TABLE users; --"
  // Or: "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin_users"
  // Should use prepared statements: db.all("SELECT * FROM users WHERE id = ?", [userId])

  const db = new sqlite3.Database(DB_CONFIG.sqlite);

  // Promisify database methods
  const dbAll = promisify(db.all.bind(db));
  const dbRun = promisify(db.run.bind(db));

  try {
    // Initialize demo database if needed
    await initializeDemoDatabase(db);

    // Determine if this is a SELECT or other query
    const isSelect = query.trim().toUpperCase().startsWith("SELECT");

    if (isSelect) {
      // 🚨 SEC-003: Direct query execution - SQL injection vulnerable
      const results = await dbAll(query);

      // 🚨 SEC-004: Information Disclosure
      // Logging query results which may contain sensitive user data
      console.log("Query results:", JSON.stringify(results, null, 2));

      return {
        content: [
          {
            type: "text",
            text: `Query Results:\n\n${JSON.stringify(results, null, 2)}`,
          },
        ],
      };
    } else {
      // 🚨 SEC-003: SQL injection for INSERT/UPDATE/DELETE
      const result = await dbRun(query);

      return {
        content: [
          {
            type: "text",
            text: `Query executed successfully\n\nAffected rows: ${result}`,
          },
        ],
      };
    }
  } finally {
    db.close();
  }
}

async function initializeDemoDatabase(db: sqlite3.Database) {
  const dbRun = promisify(db.run.bind(db));

  // Create demo tables with sensitive data
  try {
    // Users table with passwords (should be hashed, but aren't for demo)
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        api_key TEXT,
        credit_card TEXT,
        ssn TEXT
      )
    `);

    // Check if we need to insert demo data
    const dbGet = promisify(db.get.bind(db));
    const existing = await dbGet("SELECT COUNT(*) as count FROM users");

    // ✅ FIX: Type assertion for existing result
    const result = existing as DatabaseCountResult;

    if (result.count === 0) {
      // 🚨 SEC-012: Storing sensitive data in plaintext
      // Passwords should be hashed (bcrypt, argon2)
      // Credit cards should be tokenized
      // SSNs should be encrypted
      await dbRun(`
        INSERT INTO users (username, email, password, api_key, credit_card, ssn)
        VALUES
          ('admin', 'admin@example.com', 'Admin123!', 'sk-proj-admin-key-12345', '4532-1234-5678-9010', '123-45-6789'),
          ('john_doe', 'john@example.com', 'password123', 'sk-proj-user-key-67890', '5555-4444-3333-2222', '987-65-4321'),
          ('jane_smith', 'jane@example.com', 'qwerty456', 'sk-proj-jane-key-11111', '4111-1111-1111-1111', '555-55-5555')
      `);

      console.log("Demo database initialized with sample data");
    }
  } catch (error) {
    // Table might already exist
    console.log("Database initialization skipped (may already exist)");
  }
}