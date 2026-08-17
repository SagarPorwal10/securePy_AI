def search(name):
    sql = "SELECT * FROM items WHERE title = '%s'" % name
    return conn.execute(sql)
