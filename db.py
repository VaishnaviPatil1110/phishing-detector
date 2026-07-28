import sqlite3

# ======================================
# CONNECT DATABASE
# ======================================
conn = sqlite3.connect("phishing.db")
cur = conn.cursor()

# ======================================
# CREATE TABLES IF NOT EXISTS
# ======================================
cur.execute("""
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    result TEXT,
    risk_score INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS email_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_content TEXT,
    result TEXT,
    risk_score INTEGER
)
""")

conn.commit()

# ======================================
# INSERT SAMPLE DATA
# ======================================
cur.execute("""
INSERT INTO results (url, result, risk_score)
VALUES (?, ?, ?)
""", ("https://example.com", "Unknown", 0))

cur.execute("""
INSERT INTO email_results (email_content, result, risk_score)
VALUES (?, ?, ?)
""", ("Test email content", "Unknown", 0))

conn.commit()

print("Sample data inserted successfully.\n")

# ======================================
# SHOW ALL URL DATA
# ======================================
print("===== URL RESULTS =====\n")

cur.execute("SELECT * FROM results")
rows = cur.fetchall()

for row in rows:
    print(row)

# ======================================
# SHOW ALL EMAIL DATA
# ======================================
print("\n===== EMAIL RESULTS =====\n")

cur.execute("SELECT * FROM email_results")
rows = cur.fetchall()

for row in rows:
    print(row)

# ======================================
# UPDATE URL RESULT
# ======================================
cur.execute("""
UPDATE results
SET result = ?
WHERE id = ?
""", ("Safe", 1))

print("\nURL result updated.")

# ======================================
# UPDATE URL RISK SCORE
# ======================================
cur.execute("""
UPDATE results
SET risk_score = ?
WHERE id = ?
""", (15, 1))

print("URL risk score updated.")

# ======================================
# UPDATE URL
# ======================================
cur.execute("""
UPDATE results
SET url = ?
WHERE id = ?
""", ("https://google.com", 1))

print("URL updated.")

# ======================================
# UPDATE EMAIL RESULT
# ======================================
cur.execute("""
UPDATE email_results
SET result = ?
WHERE id = ?
""", ("Phishing", 1))

print("Email result updated.")

# ======================================
# UPDATE EMAIL RISK SCORE
# ======================================
cur.execute("""
UPDATE email_results
SET risk_score = ?
WHERE id = ?
""", (90, 1))

print("Email risk score updated.")

# ======================================
# UPDATE EMAIL CONTENT
# ======================================
cur.execute("""
UPDATE email_results
SET email_content = ?
WHERE id = ?
""", ("Urgent! Verify your bank account now.", 1))

print("Email content updated.")

# ======================================
# SAVE CHANGES
# ======================================
conn.commit()

# ======================================
# CHECK UPDATED ROWS
# ======================================
print("\n===== UPDATED URL RESULTS =====\n")

cur.execute("SELECT * FROM results")
rows = cur.fetchall()

for row in rows:
    print(row)

print("\n===== UPDATED EMAIL RESULTS =====\n")

cur.execute("SELECT * FROM email_results")
rows = cur.fetchall()

for row in rows:
    print(row)

# ======================================
# CLOSE DATABASE
# ======================================
conn.close()

print("\nDatabase changes saved successfully.")