import sqlite3

conexion = sqlite3.connect("tienda.db", check_same_thread=False)


def buscar_producto(nombre):
    cur = conexion.cursor()
    cur.execute("SELECT id, nombre, precio FROM productos WHERE nombre = ?", (nombre,))
    return cur.fetchall()
