def search(name):
    sql = "SELECT * FROM items WHERE title = '" + name + "'"
    return conn.execute(sql)
