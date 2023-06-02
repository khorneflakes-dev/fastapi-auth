import bcrypt
password = "12345"  # Tu contraseña en texto plano

# Genera el hash de la contraseña
hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

print(hashed_password.decode("utf-8"))  # Imprime el hash generado
