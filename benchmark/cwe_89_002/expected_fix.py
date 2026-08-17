def search(name):
    sql = "SELECT * FROM items WHERE title = ?"
    return conn.execute(sql, (name,))
