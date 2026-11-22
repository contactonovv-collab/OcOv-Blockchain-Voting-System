import sqlite3

email = input("Enter your registered email: ").strip().lower()

connection = sqlite3.connect("voting.db")

cursor = connection.cursor()

cursor.execute(
    "UPDATE users SET role = 'admin' WHERE LOWER(email) = ?",
    (email,)
)

if cursor.rowcount == 1:
    connection.commit()
    print("Admin role assigned successfully!")
elif cursor.rowcount == 0:
    print("No account found with that email.")
else:
    connection.commit()
    print("Updated multiple matching accounts.")

connection.close()