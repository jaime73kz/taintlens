import sqlite3

conexion = sqlite3.connect("tienda.db", check_same_thread=False)


def buscar_producto(nombre):
    cur = conexion.cursor()
    # Consulta armada con un f-string: inyección SQL.
    cur.execute(f"SELECT id, nombre, precio FROM productos WHERE nombre = '{nombre}'")
    return cur.fetchall()
